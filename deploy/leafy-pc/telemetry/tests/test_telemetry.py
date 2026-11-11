import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from exporter import (CPU, MEM, LIMIT, NET, LAST_SEEN, Collector, Config, ContractError, Docker,
                      inventory, line, parse_metrics, resources, started_time, fetch_cadvisor)
from verify import continuity, verify

CID = 'a' * 64
CID2 = 'b' * 64
CFG = Config('gc-fixture', 'gc-docker-fixture', 'deploy-fixture', {'backend': 'leafy-backend'})


def row(cid=CID, name='leafy-backend', service='backend'):
    return {'Id': cid, 'Names': ['/' + name], 'State': 'running',
            'Labels': {'com.docker.compose.project': CFG.project, 'com.docker.compose.service': service}}


def inspected(cid=CID, name='leafy-backend', count=0, stamp='2026-11-10T00:00:00.123456789Z', memory=1000):
    return {'Id': cid, 'Name': '/' + name, 'Config': {'Labels': row()['Labels']},
            'RestartCount': count, 'HostConfig': {'Memory': memory},
            'State': {'StartedAt': stamp, 'Running': True}}


def raw(cid=CID, cpu=0, net=0, working=900, limit=1000, interface='eth0', root=False, observed=100):
    labels = {'id': '/docker/' + cid, 'name': 'leafy-backend', 'image': 'fixture'}
    output = [line(CPU, {**labels, 'cpu': 'total'}, cpu), line(MEM, labels, working), line(LIMIT, labels, limit)]
    output.append(line(NET, {**labels, 'interface': interface}, net))
    output.append(line(LAST_SEEN, labels, observed))
    if root:
        output.append(line(NET, {'id': '/', 'interface': 'eth0'}, net))
        output.append(line(LAST_SEEN, {'id': '/'}, observed))
    return '\n'.join(output) + '\n'


class FakeDocker:
    def __init__(self):
        self.rows = [row()]
        self.info = inspected()
        self.failure = False

    def inventory(self):
        if self.failure:
            raise OSError('secret error body must not be exposed')
        return copy.deepcopy(self.rows)

    def inspect(self, cid):
        if self.failure:
            raise OSError('secret')
        return copy.deepcopy(self.info)


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.docker = FakeDocker()
        self.raw = raw()
        self.now = 100
        self.collector = Collector(CFG, self.docker, lambda: self.raw, clock=lambda: self.now)

    def samples(self, body):
        return parse_metrics(body, upstream=False)

    def get(self, body, metric):
        return [s for s in self.samples(body) if s.metric == metric]

    def test_exposition_identity_join_and_units(self):
        body = self.collector.collect()
        self.assertEqual(verify(body, CFG)['status'], 'PASS')
        for metric in (CPU, MEM, LIMIT, NET):
            s = self.get(body, metric)[0]
            self.assertEqual(s.labels['site'], CFG.site)
            self.assertEqual(s.labels['source'], CFG.source)
            self.assertEqual(s.labels['id'], '/docker/' + CID)
            self.assertEqual(s.labels['runtime'], 'container')
            self.assertEqual(s.labels['service'], 'backend')
        self.assertEqual(self.get(body, MEM)[0].value / self.get(body, LIMIT)[0].value, .9)
        self.assertEqual(self.get(body, CPU)[0].labels['cpu'], 'total')
        self.assertEqual(self.get(body, NET)[0].labels['interface'], 'eth0')
        self.assertEqual(self.get(body, 'container_name_info')[0].value, 1)

    def test_counter_increment_and_recreation_keep_stable_series(self):
        old = self.get(self.collector.collect(), 'aiops_docker_container_restarts_total')[0]
        self.docker.info['RestartCount'] = 2
        increased = self.get(self.collector.collect(), 'aiops_docker_container_restarts_total')[0]
        self.assertEqual(increased.value, 2)
        self.docker.rows = [row(CID2)]
        self.docker.info = inspected(CID2, count=0, stamp='2026-11-10T01:00:00Z')
        self.raw = raw(CID2)
        body = self.collector.collect()
        reset = self.get(body, 'aiops_docker_container_restarts_total')[0]
        self.assertEqual(reset.labels, old.labels)
        self.assertNotIn('id', reset.labels)
        self.assertEqual(reset.value, 0)
        self.assertEqual(self.get(body, 'leafy_container_identity_info')[0].labels['id'], '/docker/' + CID2)

    def test_errors_have_no_stale_resources_or_fabricated_zero(self):
        self.collector.collect()
        self.now = 105
        self.docker.failure = True
        body = self.collector.collect()
        self.assertFalse(self.get(body, CPU))
        self.assertFalse(self.get(body, 'aiops_docker_container_restarts_total'))
        self.assertEqual(self.get(body, 'aiops_docker_status_scrape_success')[0].value, 0)
        self.assertEqual({s.value for s in self.get(body, 'leafy_telemetry_last_success_timestamp_seconds')}, {100})
        self.assertNotIn('secret', body)
        self.assertEqual(verify(body, CFG)['status'], 'FAIL')

    def test_cadvisor_failure_preserves_independent_restart_health(self):
        self.collector.cadvisor = lambda: (_ for _ in ()).throw(OSError())
        body = self.collector.collect()
        self.assertFalse(self.get(body, CPU))
        self.assertEqual(self.get(body, 'aiops_docker_status_scrape_success')[0].value, 1)
        self.assertTrue(self.get(body, 'aiops_docker_container_restarts_total'))

    def test_memory_unlimited_raw_limit_not_replaced(self):
        self.docker.info['HostConfig']['Memory'] = 0
        self.raw = raw(limit=0)
        body = self.collector.collect()
        self.assertEqual(self.get(body, LIMIT)[0].value, 0)
        self.assertEqual(self.get(body, 'leafy_container_memory_limit_configured')[0].value, 0)
        self.assertTrue(any('unlimited' in w for w in verify(body, CFG)['warnings']))
        self.raw = raw(limit=1024**3)  # VM fallback remains raw, not a configured quota.
        self.assertEqual(self.get(self.collector.collect(), LIMIT)[0].value, 1024**3)

    def test_bad_resource_contracts_rejected_atomically(self):
        baseline = raw()
        cases = [baseline.replace('cpu="total"', 'cpu="cpu00"'),
                 baseline.replace('/docker/' + CID, '/system.slice/docker-' + CID + '.scope'),
                 baseline.replace('name="leafy-backend"', 'name="other"'),
                 baseline.replace('interface="eth0",', ''),
                 baseline + line(CPU, {'id': '/docker/' + CID, 'cpu': 'total', 'source': 'jh'}, 0),
                 baseline + baseline.splitlines()[0] + '\n',
                 baseline.replace('image="fixture"', 'image="other"', 1).replace('900', 'NaN'),
                 baseline.replace('} 900', ',revision="2"} 900'),
                 '\n'.join(s for s in baseline.splitlines() if not s.startswith(NET))]
        for bad in cases:
            with self.subTest(bad=bad):
                self.raw = bad
                body = self.collector.collect()
                self.assertFalse(self.get(body, CPU))
                self.assertFalse(self.get(body, 'container_name_info'))
                self.assertEqual(next(s.value for s in self.get(body, 'leafy_telemetry_collection_success')
                                      if s.labels['component'] == 'resources'), 0)

    def test_cadvisor_freshness_missing_stale_and_clock_skew(self):
        for body in (raw(observed=80), raw(observed=106),
                     '\n'.join(s for s in raw().splitlines() if not s.startswith(LAST_SEEN))):
            self.raw = body
            output = self.collector.collect()
            self.assertFalse(self.get(output, CPU))
            self.assertEqual(self.get(output, 'aiops_docker_status_scrape_success')[0].value, 1)

    def test_optional_raw_name_is_explicitly_filled_and_per_core_preserved(self):
        self.raw = raw().replace('name="leafy-backend",', '')
        self.raw += line(CPU, {'id': '/docker/' + CID, 'cpu': 'cpu00', 'image': 'fixture'}, 0)
        body = self.collector.collect()
        self.assertEqual(verify(body, CFG)['status'], 'PASS')
        self.assertEqual({s.labels['cpu'] for s in self.get(body, CPU)}, {'total', 'cpu00'})
        self.assertTrue(all(s.labels['name'] == 'leafy-backend' for s in self.get(body, CPU)))

    def test_cadvisor_get_only_no_redirect_and_timeout(self):
        with patch('exporter.http.client.HTTPConnection') as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = raw().encode()
            self.assertEqual(fetch_cadvisor('http://cadvisor:8080/metrics'), raw())
            connection.return_value.request.assert_called_with('GET', '/metrics', headers={'Accept': 'text/plain; version=0.0.4'})
            response.status = 302
            with self.assertRaises(ContractError):
                fetch_cadvisor('http://cadvisor:8080/metrics')
            connection.return_value.getresponse.side_effect = TimeoutError()
            with self.assertRaises(TimeoutError):
                fetch_cadvisor('http://cadvisor:8080/metrics')
        for url in ('http://user:secret@cadvisor/metrics', 'http://cadvisor/metrics?redirect=x'):
            with self.assertRaises(ContractError):
                fetch_cadvisor(url)

    def test_duplicate_inventory_id_name_and_inspect_race(self):
        for rows in ([row(), row()], [row(), row(CID2)]):
            with self.assertRaises(ContractError):
                inventory(rows)
        self.docker.info['Id'] = CID2
        self.assertFalse(self.get(self.collector.collect(), 'aiops_docker_container_restarts_total'))

    def test_stopped_and_never_started_container(self):
        self.docker.rows[0]['State'] = 'exited'
        self.docker.info['State'] = {'StartedAt': '0001-01-01T00:00:00Z', 'Running': False}
        body = self.collector.collect()
        self.assertFalse(self.get(body, 'aiops_docker_container_started_at_seconds'))
        self.assertEqual(self.get(body, 'aiops_docker_status_scrape_success')[0].value, 1)

    def test_partial_inspect_failure_and_target_absence(self):
        cfg = Config(CFG.site, CFG.source, CFG.project, {'backend': 'leafy-backend', 'minio': 'leafy-minio'})
        body = Collector(cfg, self.docker, lambda: self.raw).collect()
        self.assertTrue(self.get(body, 'aiops_docker_container_restarts_total'))
        self.assertEqual(self.get(body, 'aiops_docker_status_scrape_success')[0].value, 0)
        missing = [s for s in self.get(body, 'leafy_telemetry_target_present') if s.labels['service'] == 'minio']
        self.assertEqual(missing[0].value, 0)

    def test_root_is_vm_scope_without_application_name(self):
        self.raw = raw(root=True)
        body = self.collector.collect()
        root_sample = next(s for s in self.get(body, NET) if s.labels['id'] == '/')
        self.assertEqual(root_sample.labels['runtime'], 'host')
        self.assertEqual(root_sample.labels['target'], 'docker-vm')
        self.assertNotIn('name', root_sample.labels)

    def test_duplicate_sources_and_scrape_endpoints_detected(self):
        body = self.collector.collect()
        self.assertEqual(verify(body + body.replace(CFG.source, 'jh-fixture'), CFG)['status'], 'FAIL')
        first = [line(s.metric, {**s.labels, 'job': 'gc', 'instance': 'one:9108'}, s.value) for s in self.samples(body)]
        second = [line(s.metric, {**s.labels, 'job': 'gc', 'instance': 'two:9108'}, s.value) for s in self.samples(body)]
        result = verify('\n'.join(first + second), CFG)
        self.assertIn('duplicate observer scrape endpoints', result['errors'])

    def test_continuity_distinguishes_gap_and_zero(self):
        self.raw = raw(cpu=0, net=0)
        body = self.collector.collect()
        self.assertEqual(continuity([(100, body), (105, body), (110, body)], CFG)['status'], 'PASS')
        self.assertEqual(continuity([(100, body), (105, body), (120, body)], CFG)['status'], 'FAIL')
        self.assertEqual(continuity([(100, body), (105, '') , (110, body)], CFG)['status'], 'FAIL')

    def test_parser_escaping_and_reserved_labels(self):
        body = line(NET, {'id': '/', 'interface': 'eth"\\\n'}, 0)
        self.assertEqual(parse_metrics(body)[0].labels['interface'], 'eth"\\\n')
        for bad in ('container_memory_working_set_bytes{id="/",id="/"} 0',
                    'container_memory_working_set_bytes{id="/"} Inf',
                    'container_memory_working_set_bytes{id="/"} 0 123',
                    'container_memory_working_set_bytes{id="/",job="jh"} 0'):
            with self.assertRaises((ValueError, ContractError)):
                parse_metrics(bad)

    def test_config_requires_real_values_and_excludes_host_db(self):
        with self.assertRaises(ContractError):
            Config.load(ROOT / 'config.example.json')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            for targets in ({'db': 'leafy-db'}, {'backend': 'x', 'minio': 'x'}):
                path.write_text(json.dumps({**CFG.__dict__, 'targets': targets}))
                with self.assertRaises(ContractError):
                    Config.load(path)

    def test_rfc3339nano_and_invalid_started_time(self):
        self.assertEqual(started_time('0001-01-01T00:00:00Z'), None)
        self.assertEqual(started_time('2026-11-10T00:00:00.123456789Z'), started_time('2026-11-10T09:00:00.123456+09:00'))
        with self.assertRaises(ContractError):
            started_time('bad time')

    def test_read_only_docker_transport(self):
        if not hasattr(socket, 'AF_UNIX'):
            self.skipTest('Unix socket unavailable')
        from socketserver import UnixStreamServer
        paths = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append((self.command, self.path))
                data = json.dumps([row()] if self.path.startswith('/containers/json?') else inspected()).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *_):
                pass
        with tempfile.TemporaryDirectory(prefix='oi23-', dir='/private/tmp') as tmp:
            path = str(Path(tmp) / 'd.sock')
            server = UnixStreamServer(path, Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                docker = Docker(path)
                self.assertEqual(docker.inventory()[0]['Id'], CID)
                self.assertEqual(docker.inspect(CID)['RestartCount'], 0)
                with self.assertRaises(ContractError):
                    docker.get('/containers/' + CID + '/restart')
                self.assertEqual([method for method, _ in paths], ['GET', 'GET'])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


class NativePromQLTests(unittest.TestCase):
    """Exact M2 expressions, only job/instance selectors changed in temp files.

    Samples are actual collector output at synthetic 5s capture times. No Docker
    daemon, container start, Prometheus server, or running rule is required.
    """
    @classmethod
    def setUpClass(cls):
        cls.promtool = os.environ.get('OI_PROMTOOL')
        if not cls.promtool:
            raise unittest.SkipTest('set OI_PROMTOOL for native PromQL validation')
        import yaml
        cls.yaml = yaml
        repo = ROOT.parents[2]
        cls.rules = []
        for name in ('prometheus.infra.rules.yml', 'prometheus.resources.rules.yml'):
            cls.rules.extend(yaml.safe_load((repo / 'docs/rulepack/m2/generated' / name).read_text())['groups'][0]['rules'])

    def expression(self, alert, target=None):
        rule = next(r for r in self.rules if r['alert'] == alert and
                    (target is None or r['labels'].get('rulepack_target') == target))
        expr = rule['expr']
        expr = expr.replace('instance="cadvisor:8080", job="cadvisor"', 'instance="gc-fixture:9108", job="gc-docker-telemetry"')
        expr = expr.replace('instance="pipeline:8000", job="pipeline-metadata"', 'instance="gc-fixture:9108", job="gc-docker-telemetry"')
        return expr

    def evaluate(self, alert, bodies, expected, target=None, evaluation='10s'):
        series = {}
        for index, body in enumerate(bodies):
            for s in parse_metrics(body, upstream=False):
                labelset = {**s.labels, 'job': 'gc-docker-telemetry', 'instance': 'gc-fixture:9108'}
                key = line(s.metric, labelset, 0).rsplit(' ', 1)[0]
                series.setdefault(key, ['stale'] * len(bodies))[index] = str(s.value)
        test = {'evaluation_interval': '5s', 'tests': [{'interval': '5s',
                'input_series': [{'series': key, 'values': ' '.join(values)} for key, values in series.items()],
                'promql_expr_test': [{'expr': self.expression(alert, target), 'eval_time': evaluation,
                                     'exp_samples': expected}]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'test.yml'
            path.write_text(self.yaml.safe_dump(test))
            result = subprocess.run([self.promtool, 'test', 'rules', str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def bodies(self, counts=(0, 0, 0), stamps=None, limit=1000, interface='eth0', root=False, root_only=False, recreate=False):
        docker = FakeDocker()
        output = []
        for i, count in enumerate(counts):
            cid = CID2 if recreate and i else CID
            docker.rows = [row(cid)]
            stamp = '2026-11-10T00:00:00Z' if stamps is None else stamps[i]
            docker.info = inspected(cid, count=count, stamp=stamp)
            resource = raw(cid=cid, cpu=i * 4, net=i * 100000000, limit=limit, interface=interface, root=root, observed=100 + i * 5)
            if root_only:
                resource = '\n'.join(s for s in resource.splitlines() if not s.startswith(NET) or 'id="/"' in s)
            output.append(Collector(CFG, docker, lambda: resource, clock=lambda: 100 + i * 5).collect())
        return output

    def test_cpu_core_seconds_irate_and_metadata_join(self):
        self.evaluate('HighCpuUsage', self.bodies(), [{'labels': '{name="leafy-backend"}', 'value': .8}], 'leafy-backend')

    def test_memory_ratio_and_zero_limit(self):
        self.evaluate('HighMemoryUsage', self.bodies(), [{'labels': '{name="leafy-backend"}', 'value': .9}])
        self.evaluate('HighMemoryUsage', self.bodies(limit=0), [])

    def test_network_bytes_per_second_and_loopback_guard(self):
        self.evaluate('HighNetworkReceive', self.bodies(counts=(0,) * 13), [{'labels': '{name="leafy-backend"}', 'value': 20000000}], evaluation='1m')
        self.evaluate('HighNetworkReceive', self.bodies(counts=(0,) * 13, interface='lo', root=True), [], evaluation='1m')

    def test_root_fallback_keeps_host_identity(self):
        labels = '{id="/",instance="gc-fixture:9108",job="gc-docker-telemetry",runtime="host",service="docker-vm",site="gc-fixture",source="gc-docker-fixture",target="docker-vm"}'
        self.evaluate('HighNetworkReceive', self.bodies(counts=(0,) * 13, root=True, root_only=True), [{'labels': labels, 'value': 20000000}], evaluation='1m')

    def test_restart_increment_and_reset_keep_original_condition(self):
        self.evaluate('ContainerRestarted', self.bodies(counts=(0, 1, 2)), [{'labels': '{name="leafy-backend"}', 'value': 2}], 'leafy-backend')
        self.evaluate('ContainerRestarted', self.bodies(counts=(5, 0, 2), recreate=True), [{'labels': '{name="leafy-backend"}', 'value': 2}], 'leafy-backend')
        self.evaluate('ContainerRestarted', self.bodies(counts=(5, 0, 1), recreate=True), [], 'leafy-backend')

    def test_started_at_changes_without_counter_increase(self):
        stamps = ['2026-11-10T00:00:00Z', '2026-11-10T00:01:00Z', '2026-11-10T00:02:00Z']
        self.evaluate('ContainerRestarted', self.bodies(stamps=stamps), [{'labels': '{name="leafy-backend"}', 'value': 2}], 'leafy-backend')

    def test_gc_fixture_does_not_validate_integrated_docker_db_cpu(self):
        self.evaluate('HighCpuUsage', self.bodies(), [], 'leafy-db')

    def test_source_selectors_exclude_jh_series_with_same_name(self):
        bodies = self.bodies()
        expr = self.expression('HighCpuUsage', 'leafy-backend')
        with tempfile.TemporaryDirectory() as tmp:
            samples = []
            for job, instance, site, source in [('gc-docker-telemetry', 'gc-fixture:9108', CFG.site, CFG.source),
                                                ('jh-local', 'jh-fixture:8000', 'jh-fixture', 'jh-local')]:
                all_series = {}
                for body in bodies:
                    for sample in parse_metrics(body, upstream=False):
                        labels = {**sample.labels, 'job': job, 'instance': instance, 'site': site, 'source': source}
                        key = line(sample.metric, labels, 0).rsplit(' ', 1)[0]
                        all_series.setdefault(key, []).append(str(sample.value))
                samples.extend({'series': key, 'values': ' '.join(values)} for key, values in all_series.items())
            spec = {'evaluation_interval': '5s', 'tests': [{'interval': '5s', 'input_series': samples,
                    'promql_expr_test': [{'expr': expr, 'eval_time': '10s',
                    'exp_samples': [{'labels': '{name="leafy-backend"}', 'value': .8}]}]}]}
            path = Path(tmp) / 'source.yml'
            path.write_text(self.yaml.safe_dump(spec))
            result = subprocess.run([self.promtool, 'test', 'rules', str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_absent_scrape_does_not_become_zero(self):
        self.evaluate('HighCpuUsage', ['', '', ''], [], 'leafy-backend')
        self.evaluate('HighMemoryUsage', ['', '', ''], [])


if __name__ == '__main__':
    unittest.main()
