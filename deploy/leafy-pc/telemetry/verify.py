#!/usr/bin/env python3
"""Validate saved collector exposition. No network or Docker mutation.

Run against each saved scrape separately. Prometheus-added job/instance labels
are optional; when present exactly one pair must represent this observer.
"""
import argparse
import json
from pathlib import Path
from exporter import CPU, MEM, LIMIT, NET, LAST_SEEN, CID, Config, ContractError, parse_metrics


def verify(body, cfg, observed_at=None):
    samples = parse_metrics(body, upstream=False)
    errors, warnings = [], []
    endpoints = set()
    identities, metadata, resources = {}, {}, []
    for sample in samples:
        labels = sample.labels
        if labels.get('site') != cfg.site or labels.get('source') != cfg.source:
            errors.append('unexpected site/source')
        if 'job' in labels or 'instance' in labels:
            endpoints.add((labels.get('job'), labels.get('instance')))
        if sample.metric == 'container_name_info':
            cid = labels.get('id')
            if cid in metadata or sample.value != 1:
                errors.append('duplicate id or metadata value != 1')
            metadata[cid] = labels
            if (not isinstance(cid, str) or not cid.startswith('/docker/')
                    or not CID.fullmatch(cid[len('/docker/'):])
                    or labels.get('runtime') != 'container'
                    or not labels.get('name') or labels.get('target') != labels.get('name')):
                errors.append('invalid metadata identity')
        if sample.metric == 'leafy_container_identity_info':
            name = labels.get('name')
            if name in identities:
                errors.append('duplicate target identity')
            identities[name] = labels
        if sample.metric in (CPU, MEM, LIMIT, NET, LAST_SEEN):
            resources.append(sample)
    if len(endpoints) > 1:
        errors.append('duplicate observer scrape endpoints')
    names = [labels.get('name') for labels in metadata.values()]
    if len(names) != len(set(names)):
        errors.append('duplicate metadata name')
    for sample in resources:
        labels = sample.labels
        cid = labels.get('id', '')
        if cid == '/':
            if (sample.metric not in (NET, LAST_SEEN) or labels.get('runtime') != 'host'
                    or labels.get('target') != 'docker-vm' or 'name' in labels):
                errors.append('root attributed to application container')
        else:
            meta = metadata.get(cid)
            if meta is None or any(meta.get(k) != labels.get(k) for k in ('name', 'service', 'target', 'runtime')):
                errors.append('resource/metadata mismatch')
        if sample.metric == LAST_SEEN and observed_at is not None and not -5 <= observed_at - sample.value <= 15:
            errors.append('cAdvisor freshness/clock skew invalid')
        if sample.metric == CPU and not labels.get('cpu'):
            errors.append('CPU dimension missing')
        if sample.metric == NET and not labels.get('interface'):
            errors.append('network interface missing')
    mem_keys = [{tuple(sorted(s.labels.items())) for s in resources if s.metric == metric} for metric in (MEM, LIMIT)]
    if mem_keys[0] != mem_keys[1]:
        errors.append('memory full-label mismatch')
    for metric in (CPU, MEM, LIMIT, NET, LAST_SEEN):
        if not any(s.metric == metric for s in resources):
            errors.append('resource family missing: ' + metric)
    for service, name in cfg.targets.items():
        expected = {'runtime': 'container', 'service': service, 'name': name, 'target': name}
        for metric in ('leafy_telemetry_target_present', 'leafy_telemetry_target_scrape_success'):
            match = [s for s in samples if s.metric == metric and all(s.labels.get(k) == v for k, v in expected.items())]
            if len(match) != 1 or match[0].value != 1:
                errors.append('target missing/unhealthy: ' + name)
        if name not in identities:
            errors.append('target identity missing: ' + name)
        for metric in ('aiops_docker_container_restarts_total', 'aiops_docker_container_started_at_seconds'):
            match = [s for s in samples if s.metric == metric and all(s.labels.get(k) == v for k, v in expected.items())]
            if len(match) != 1 or 'id' in match[0].labels:
                errors.append('restart stable series missing/invalid: ' + name)
        cpu = [s for s in resources if s.metric == CPU and s.labels.get('name') == name and s.labels.get('cpu') == 'total']
        if not cpu:
            errors.append('cpu=total missing: ' + name)
    for component in ('docker', 'resources'):
        match = [s for s in samples if s.metric == 'leafy_telemetry_collection_success' and s.labels.get('component') == component]
        if len(match) != 1 or match[0].value != 1:
            errors.append('producer component failed: ' + component)
    if any(s.metric == 'leafy_container_memory_limit_configured' and s.value == 0 for s in samples):
        warnings.append('unlimited target: positive cAdvisor VM limit is not a configured container limit')
    docker_net = [s for s in resources if s.metric == NET and s.labels.get('id', '').startswith('/docker/')]
    root_net = [s for s in resources if s.metric == NET and s.labels.get('id') == '/']
    if docker_net:
        warnings.append('original root fallback blocked by ANY /docker/ network series, including lo/unwatched names')
    elif root_net:
        warnings.append('network root fallback is Docker VM scope; no per-container network proof')
    return {'status': 'FAIL' if errors else 'PASS', 'errors': sorted(set(errors)),
            'warnings': sorted(set(warnings)), 'sample_count': len(samples),
            'runtime_accepted': False}  # Snapshot validation is not runtime acceptance.


def continuity(bodies, cfg, interval=5):
    """Capture times are provided by caller. Not a restart event reconstruction."""
    errors = []
    if len(bodies) < 3:
        errors.append('at least three timestamped captures required')
    for (before, _), (after, _) in zip(bodies, bodies[1:]):
        if after <= before or after - before > interval * 1.5:
            errors.append('capture gap or non-increasing timestamp')
    for captured_at, body in bodies:
        if verify(body, cfg, observed_at=captured_at)['status'] != 'PASS':
            errors.append('unhealthy capture')
    return {'status': 'FAIL' if errors else 'PASS', 'errors': sorted(set(errors)), 'runtime_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('snapshot', nargs='?')
    parser.add_argument('--captures', help='JSON array: [{timestamp: epoch seconds, path: relative snapshot path}]')
    args = parser.parse_args()
    try:
        cfg = Config.load(args.config)
        if args.captures:
            manifest = Path(args.captures)
            captures = json.loads(manifest.read_text(encoding='utf-8-sig'))
            bodies = [(float(c['timestamp']), (manifest.parent / c['path']).read_text()) for c in captures]
            result = continuity(bodies, cfg)
        elif args.snapshot:
            result = verify(Path(args.snapshot).read_text(), cfg)
        else:
            raise ValueError('snapshot or --captures required')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {'status': 'FAIL', 'errors': [type(exc).__name__], 'runtime_accepted': False}
    print(json.dumps(result, indent=2))
    raise SystemExit(result['status'] != 'PASS')


if __name__ == '__main__':
    main()
