#!/usr/bin/env python3
"""GC Docker/cAdvisor read-only collector. No third-party dependencies.

Only GET /containers/json and GET /containers/<full-id>/json are issued to Docker.
No previous resource/restart samples are cached or synthesized on failure.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
from pathlib import Path
import re
import socket
import time
from urllib.parse import urlencode, urlsplit

CPU = 'container_cpu_usage_seconds_total'
MEM = 'container_memory_working_set_bytes'
LIMIT = 'container_spec_memory_limit_bytes'
NET = 'container_network_receive_bytes_total'
LAST_SEEN = 'container_last_seen'
RESOURCE_TYPES = {CPU: 'counter', MEM: 'gauge', LIMIT: 'gauge', NET: 'counter', LAST_SEEN: 'gauge'}
CID = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
RESERVED = {'site', 'source', 'runtime', 'target', 'service', 'job', 'instance',
            'exported_job', 'exported_instance'}
LINE = re.compile(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+([0-9]+))?\s*\Z')
LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\[\\"n])*)"\s*(,|$)')


class ContractError(ValueError):
    pass


@dataclass(frozen=True)
class Sample:
    metric: str
    labels: dict[str, str]
    value: float


def parse_metrics(body: str, upstream: bool = True) -> list[Sample]:
    """Strict Prometheus 0.0.4 subset, only approved resource/freshness families.

    Explicit timestamps are rejected: timestamp freshness must be the scrape time.
    All label keys are checked before any privacy filtering or enrichment.
    """
    samples = []
    seen = set()
    for line in body.splitlines():
        if not line or line.startswith('#'):
            continue
        prefix = re.split(r'[\s{]', line, maxsplit=1)[0]
        if upstream and prefix not in RESOURCE_TYPES:
            continue
        match = LINE.fullmatch(line)
        if not match or match[4]:
            raise ContractError('invalid exposition or explicit timestamp')
        labels = {}
        text = match[2] or ''
        pos = 0
        while pos < len(text):
            item = LABEL.match(text, pos)
            if not item or item[1] in labels:
                raise ContractError('invalid or duplicate label')
            labels[item[1]] = re.sub(r'\\([\\"n])', lambda m: '\n' if m[1] == 'n' else m[1], item[2])
            pos = item.end()
        if upstream and RESERVED.intersection(labels):
            raise ContractError('upstream identity/source label collision')
        if upstream and 'id' not in labels:
            raise ContractError('missing id')
        value = float(match[3])
        if not math.isfinite(value) or value < 0:
            raise ContractError('nonfinite or negative resource sample')
        key = (match[1], tuple(sorted(labels.items())))
        if key in seen:
            raise ContractError('duplicate resource series')
        seen.add(key)
        samples.append(Sample(match[1], labels, value))
    return samples


def line(metric: str, labels: dict[str, str], value: float | int) -> str:
    def escape(s):
        return s.replace('\\', '\\\\').replace('\n', '\\n').replace('"', '\\"')
    encoded = ','.join(f'{k}="{escape(v)}"' for k, v in sorted(labels.items()))
    return f'{metric}{{{encoded}}} {value}'


def started_time(value: str) -> float | None:
    if value.startswith('0001-01-01'):
        return None
    if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)', value):
        raise ContractError('invalid StartedAt')
    value = re.sub(r'(\.\d{6})\d+', r'\1', value)
    result = datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    if not math.isfinite(result) or result <= 0:
        raise ContractError('invalid StartedAt epoch')
    return result


@dataclass(frozen=True)
class Config:
    site: str
    source: str  # Stable observer/daemon identity, NOT the scrape address.
    project: str
    targets: dict[str, str]  # Observed Compose service -> exact Docker name.

    @classmethod
    def load(cls, path):
        raw = json.loads(Path(path).read_text(encoding='utf-8-sig'))
        if set(raw) != {'site', 'source', 'project', 'targets'}:
            raise ContractError('unexpected config fields')
        cfg = cls(**raw)
        if not all(isinstance(v, str) and NAME.fullmatch(v) and 'REPLACE' not in v
                   for v in (cfg.site, cfg.source, cfg.project)):
            raise ContractError('set observed site/source/project')
        if not isinstance(cfg.targets, dict) or not cfg.targets or not set(cfg.targets) <= {'frontend', 'backend', 'minio'}:
            raise ContractError('only GC container frontend/backend/minio are supported; host DB is excluded')
        if not all(isinstance(n, str) and NAME.fullmatch(n) and 'REPLACE' not in n for n in cfg.targets.values()):
            raise ContractError('set exact observed Docker names')
        if len(set(cfg.targets.values())) != len(cfg.targets):
            raise ContractError('duplicate target name')
        return cfg

    def base(self):
        return {'site': self.site, 'source': self.source}


class Docker:
    def __init__(self, path='/var/run/docker.sock', timeout=0.5):
        self.path, self.timeout = path, timeout

    def get(self, path):
        # Fixed GET paths only. Socket :ro is NOT an API authorization boundary.
        if not (path.startswith('/containers/json?') or re.fullmatch(r'/containers/[0-9a-f]{64}/json', path)):
            raise ContractError('Docker endpoint is not allowlisted')
        conn = http.client.HTTPConnection('localhost', timeout=self.timeout)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
            conn.sock = sock
            conn.request('GET', path)
            response = conn.getresponse()
            if response.status != 200:
                raise ContractError('Docker GET failed')
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ContractError('Docker response too large')
            return json.loads(data)
        finally:
            conn.close()
            sock.close()

    def inventory(self):
        return self.get('/containers/json?' + urlencode({'all': 'true'}))

    def inspect(self, cid):
        return self.get(f'/containers/{cid}/json')


def fetch_cadvisor(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'http' or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ContractError('cAdvisor must be an internal HTTP endpoint without credentials')
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=1)
    try:
        conn.request('GET', parsed.path or '/metrics', headers={'Accept': 'text/plain; version=0.0.4'})
        resp = conn.getresponse()
        if resp.status != 200:  # No redirects/proxies.
            raise ContractError('cAdvisor GET failed')
        data = resp.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise ContractError('cAdvisor response too large')
        return data.decode('utf-8')
    finally:
        conn.close()


def inventory(rows):
    """Keep all Docker containers for original memory scope and network guard."""
    by_id, names = {}, set()
    for row in rows:
        cid = row.get('Id', '')
        name = (row.get('Names') or [''])[0].lstrip('/')
        if not CID.fullmatch(cid) or not NAME.fullmatch(name):
            raise ContractError('invalid Docker id/name')
        if cid in by_id or name in names:
            raise ContractError('duplicate Docker id/name')
        labels = row.get('Labels') or {}
        by_id[cid] = {'name': name, 'project': labels.get('com.docker.compose.project', ''),
                      'service': labels.get('com.docker.compose.service', 'unknown'),
                      'running': row.get('State') == 'running'}
        names.add(name)
    return by_id


def identity(cfg, item):
    return {**cfg.base(), 'runtime': 'container', 'name': item['name'],
            'target': item['name'], 'service': item['service']}


def resources(cfg, items, raw, now=None):
    now = time.time() if now is None else now
    parsed = parse_metrics(raw)
    out = []
    memory_keys = {MEM: set(), LIMIT: set()}
    coverage = {cid: set() for cid, item in items.items() if item['running']}
    normalized = set()
    for sample in parsed:
        labels = sample.labels
        raw_id = labels['id']
        if raw_id == '/':
            if sample.metric not in (NET, LAST_SEEN):
                continue
            extra = {**cfg.base(), 'runtime': 'host', 'target': 'docker-vm', 'service': 'docker-vm'}
            # No name on root: it cannot be interpreted as an application container.
        elif raw_id.startswith('/docker/'):
            cid = raw_id[len('/docker/'):]
            if cid not in items or not CID.fullmatch(cid):
                raise ContractError('cAdvisor id has no exact Docker metadata match')
            item = items[cid]
            if not item['running']:
                raise ContractError('cAdvisor/Docker running-state race')
            if labels.get('name') and labels['name'] != item['name']:
                raise ContractError('cAdvisor/Docker name mismatch')
            extra = identity(cfg, item)
            if sample.metric != CPU or labels.get('cpu') == 'total':
                coverage[cid].add(sample.metric)
        else:
            # Generic cgroups do not match M2 selectors. Known Docker id under a
            # different cgroup path MUST NOT be silently rewritten to /docker/.
            if any(cid in raw_id for cid in items):
                raise ContractError('unsupported Docker cgroup id layout')
            continue
        if sample.metric == LAST_SEEN and not -5 <= now - sample.value <= 15:
            raise ContractError('cAdvisor sample stale or clock skew exceeds bounds')
        if sample.metric == CPU and not labels.get('cpu'):
            raise ContractError('CPU dimension missing')
        if sample.metric == NET and not labels.get('interface'):
            raise ContractError('network interface missing')
        if sample.metric in (MEM, LIMIT):
            memory_keys[sample.metric].add(tuple(sorted(labels.items())))
        # Remove Docker label payloads (may include secrets), but preserve all
        # other dimensions. Check full-label memory matching BEFORE this removal.
        clean = {k: v for k, v in labels.items() if not k.startswith('container_label_') and k != 'name'}
        clean.update(extra)
        key = (sample.metric, tuple(sorted(clean.items())))
        if key in normalized:
            raise ContractError('normalization created duplicate series')
        normalized.add(key)
        out.append(line(sample.metric, clean, sample.value))
    if any(s.metric == NET and s.labels.get('id') == '/' for s in parsed) and not any(
            s.metric == LAST_SEEN and s.labels.get('id') == '/' for s in parsed):
        raise ContractError('root network freshness missing')
    if not any(s.metric == NET for s in parsed):
        raise ContractError('network family missing')
    if memory_keys[MEM] != memory_keys[LIMIT]:
        raise ContractError('working_set/limit full-label mismatch')
    required = {CPU, MEM, LIMIT, LAST_SEEN}
    if not coverage or any(not required <= metrics for metrics in coverage.values()):
        raise ContractError('running Docker CPU/memory coverage incomplete')
    for cid, item in items.items():
        if item['running']:
            out.append(line('container_name_info', {**identity(cfg, item), 'id': '/docker/' + cid}, 1))
    return out


class Collector:
    def __init__(self, cfg, docker, cadvisor, clock=time.time):
        self.cfg, self.docker, self.cadvisor, self.clock = cfg, docker, cadvisor, clock
        self.last_success = {'docker': 0, 'resources': 0}

    def collect(self):
        cfg, output = self.cfg, []
        ok = {'docker': 0, 'resources': 0}
        items = None
        try:
            items = inventory(self.docker.inventory())
        except Exception:
            pass  # Error bodies/inspect payloads can contain secrets; never print.
        if items is not None:
            try:
                resource_lines = resources(cfg, items, self.cadvisor(), now=self.clock())
                output.extend(resource_lines)
                ok['resources'] = 1
            except Exception:
                pass  # Atomic rejection: avoid enabling root fallback on partial data.
            ok['docker'] = 1
        for service, name in sorted(cfg.targets.items()):
            target_labels = {**cfg.base(), 'runtime': 'container', 'service': service, 'target': name, 'name': name}
            candidates = [] if items is None else [
                (cid, item) for cid, item in items.items()
                if item['project'] == cfg.project and item['service'] == service and item['name'] == name]
            present = len(candidates) == 1
            output.append(line('leafy_telemetry_target_present', target_labels, int(present)))
            success = 0
            if present:
                cid, item = candidates[0]
                try:
                    info = self.docker.inspect(cid)
                    # Verify inspect and list refer to the same object/configuration.
                    inspected_labels = info['Config']['Labels']
                    if (info['Id'] != cid or info['Name'].lstrip('/') != name
                            or inspected_labels.get('com.docker.compose.project') != cfg.project
                            or inspected_labels.get('com.docker.compose.service') != service):
                        raise ContractError('inspect identity mismatch')
                    count = info['RestartCount']
                    if type(count) is not int or count < 0:
                        raise ContractError('invalid RestartCount')
                    limit = info['HostConfig']['Memory']
                    if type(limit) is not int or limit < 0:
                        raise ContractError('invalid configured memory limit')
                    stamp = started_time(info['State']['StartedAt'])
                    if stamp is None and info['State'].get('Running'):
                        raise ContractError('running container has no StartedAt')
                    # Stable series deliberately omit id, so recreate/reset and
                    # StartedAt changes remain visible to the existing M2 rule.
                    output.append(line('aiops_docker_container_restarts_total', target_labels, count))
                    if stamp is not None:
                        output.append(line('aiops_docker_container_started_at_seconds', target_labels, stamp))
                    output.append(line('leafy_docker_container_memory_limit_bytes', target_labels, limit))
                    output.append(line('leafy_container_memory_limit_configured', target_labels, int(limit > 0)))
                    output.append(line('leafy_container_identity_info', {**target_labels, 'id': '/docker/' + cid}, 1))
                    success = 1
                except Exception:
                    ok['docker'] = 0
            else:
                ok['docker'] = 0
            output.append(line('leafy_telemetry_target_scrape_success', target_labels, success))
        now = self.clock()
        for component, success in ok.items():
            if success:
                self.last_success[component] = now
            labels = {**cfg.base(), 'component': component}
            output.append(line('leafy_telemetry_collection_success', labels, success))
            output.append(line('leafy_telemetry_last_success_timestamp_seconds', labels, self.last_success[component]))
        output.append(line('aiops_docker_status_scrape_success', cfg.base(), ok['docker']))
        # No resource/restart cache. A successful HTTP scrape may still report
        # collection_success=0; Prometheus up alone does not prove Docker health.
        header = [f'# TYPE {metric} {kind}' for metric, kind in {
            **RESOURCE_TYPES, 'container_name_info': 'gauge',
            'aiops_docker_container_restarts_total': 'counter',
            'aiops_docker_container_started_at_seconds': 'gauge',
            'leafy_container_identity_info': 'gauge',
            'leafy_docker_container_memory_limit_bytes': 'gauge',
            'leafy_container_memory_limit_configured': 'gauge',
            'leafy_telemetry_target_present': 'gauge',
            'leafy_telemetry_target_scrape_success': 'gauge',
            'leafy_telemetry_collection_success': 'gauge',
            'leafy_telemetry_last_success_timestamp_seconds': 'gauge',
            'aiops_docker_status_scrape_success': 'gauge'}.items()]
        return '\n'.join(header + output) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--docker-socket', default='/var/run/docker.sock')
    parser.add_argument('--cadvisor', default='http://cadvisor:8080/metrics')
    parser.add_argument('--listen', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9108)
    args = parser.parse_args()
    cfg = Config.load(args.config)
    collector = Collector(cfg, Docker(args.docker_socket), lambda: fetch_cadvisor(args.cadvisor))
    # Single collection worker with hard HTTP response deadline. A timed-out
    # worker is never duplicated; subsequent requests fail until it finishes.
    executor = ThreadPoolExecutor(max_workers=1)
    pending = None

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal pending
            if self.path != '/metrics':
                self.send_error(404)
                return
            if pending is not None and not pending.done():
                self.send_error(503, 'Collection still running')
                return
            pending = executor.submit(collector.collect)
            try:
                body = pending.result(timeout=3).encode()
            except FutureTimeout:
                self.send_error(503, 'Collection deadline exceeded')
                return
            except Exception:
                self.send_error(503, 'Collection failed')
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    HTTPServer((args.listen, args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
