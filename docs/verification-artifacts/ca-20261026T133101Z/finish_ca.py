"""Resume evidence checks only. This script does not invoke any transfer."""
from pathlib import Path

source_path=Path(__file__).with_name('verify_ca.py')
source=source_path.read_text(encoding='utf8')
ns={'__file__':str(source_path),'__name__':'ca_evidence_only'}
exec(compile(source.split("assert git('branch'")[0],str(source_path),'exec'),ns)
exec('''
preflight=json.loads((OUT/'preflight.json').read_text(encoding='utf8'))
window_start=preflight['window_start_ms']
backend_ip=preflight['backend_ip']
client=docker.from_env()
samples=[json.loads(l) for l in (OUT/'observations.jsonl').read_text(encoding='utf8').splitlines()]
baseline_alerts=json.loads((OUT/'alertmanager-baseline.json').read_text(encoding='utf8'))
baseline_panels=json.loads((OUT/'grafana-baseline.json').read_text(encoding='utf8'))
dashboard=json.loads((OUT/'dashboard-baseline.json').read_text(encoding='utf8'))
captured=[json.loads((OUT/'transfer.json').read_text(encoding='utf8'))]
run_start=datetime.fromisoformat(captured[0]['invoked_at']).timestamp()
record=json.loads(next((OUT/'results').glob('*_runs.jsonl')).read_text(encoding='utf8'))
assert record['scenario']=='C-a' and record['outcome']=='TN' and record['mttd_seconds'] is None
ingested=[(None,next(x['checked_at'] for x in samples if x['log_counts']['connection']>=8 and x['log_counts']['connection_threshold']>=8))]
wait_after_ingestion=preflight['post_ingestion_observation_seconds']
logs=json.loads((OUT/'loki-network-events.json').read_text(encoding='utf8'))
entries=[json.loads(line) for stream in logs['data']['result'] for _,line in stream['values']]
connections=[e for e in entries if e['event_type']=='connection']
thresholds=[e for e in entries if e['event_type']=='connection_threshold']
assert len(connections)==8 and len(thresholds)==8
panel_snapshot_at=samples[-1]['checked_at']
snapshot_end_ms=int(datetime.fromisoformat(panel_snapshot_at).timestamp()*1000)
real_panel_query=panel_query
def panel_query(panel_id,experiment_id='.*',end_ms=None):
    return real_panel_query(panel_id,experiment_id,end_ms or snapshot_end_ms)
''',ns)
exec(compile(source[source.index("zeek=client.containers.get"):],str(source_path),'exec'),ns)
ns['summary']['panel_snapshot_at']=ns['panel_snapshot_at']
ns['summary']['capture_note']='Panel queries use actual observation end time; alert API remains live. No transfer rerun.'
ns['save']('summary.json',ns['summary'])
