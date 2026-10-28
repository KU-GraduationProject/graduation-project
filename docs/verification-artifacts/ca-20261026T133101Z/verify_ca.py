"""Read-only instrumentation around exactly one existing C-a CLI execution."""
import copy
from datetime import datetime, timezone
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

import docker
import yaml

OUT = Path(__file__).parent
ROOT = OUT.parents[1] / 'graduation-project'
NAMES = {'UnauthorizedDataTransfer', 'UnauthorizedTransferEarly'}
HEAD = '8c64545a5399703cf16fd7e137ccf7540732fb17'
env = dict(l.split('=',1) for l in (ROOT/'.env').read_text(encoding='utf-8-sig').splitlines() if '=' in l and not l.startswith('#'))
pw = env.get('GRAFANA_PASSWORD','admin').strip().strip('"').strip("'")
AUTH = {'Authorization':'Basic '+base64.b64encode(('admin:'+pw).encode()).decode()}

def now():
    return datetime.now(timezone.utc).isoformat()

def save(name, value):
    (OUT/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf8')

def get(url, body=None):
    headers = {**AUTH} if ':3000/' in url else {}
    if body is not None:
        headers['Content-Type']='application/json'
    req = urllib.request.Request(url, headers=headers, data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req,timeout=20) as response:
        return json.load(response)

def grafana(path, body=None):
    return get('http://localhost:3000'+path,body)

def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT).decode('utf8').strip()

def network_group(rules):
    return next(g for g in rules['data']['groups'] if g['name']=='network-allowlist-alerts')

def identity(alert):
    return (alert['fingerprint'],alert['startsAt'],json.dumps(alert['labels'],sort_keys=True))

dashboard_path = ROOT/'monitoring/grafana/provisioning/dashboards/aiops_dashboard.json'
dashboard = json.loads(dashboard_path.read_text(encoding='utf8'))
window_start = int((time.time()-86400)*1000)  # Fixed start avoids ageing old TP samples out during comparison.
checks = {}

def panel_query(panel_id, experiment_id='.*', end_ms=None):
    panel = next(p for p in dashboard['panels'] if p['id']==panel_id)
    targets = copy.deepcopy(panel['targets'])
    for target in targets:
        target['intervalMs']=30000
        target['maxDataPoints']=5000
        if 'expr' in target:
            target['expr']=target['expr'].replace('$__range','86400s').replace('${experiment_id}',experiment_id)
    result = grafana('/api/ds/query',{'from':str(window_start),'to':str(end_ms or int(time.time()*1000)),'queries':targets})
    assert all(r.get('status')==200 and not r.get('error') for r in result['results'].values()), result
    return result

def frames(result, ref='A'):
    return result['results'][ref].get('frames',[])

def numeric(result, ref='A'):
    for frame in frames(result,ref):
        for field,values in zip(frame['schema']['fields'],frame['data']['values']):
            if field['type']=='number' and values:
                return values[-1]
    return None

def rows(result):
    result_rows=[]
    for frame in frames(result):
        names=[f['name'] for f in frame['schema']['fields']]
        result_rows.extend(dict(zip(names,v)) for v in zip(*frame['data']['values']))
    return result_rows

def network_logs(start, end=None):
    query='{log_type="network", src_service="backend"} | json | __error__="" | dst_ip="10.210.0.30" | dst_port=8080'
    params={'query':query,'start':str(int(start*1e9)),'end':str(int((end or time.time())*1e9)),
            'direction':'forward','limit':1000}
    result=get('http://localhost:3100/loki/api/v1/query_range?'+urllib.parse.urlencode(params))
    assert result['status']=='success'
    entries=[json.loads(line) for stream in result['data']['result'] for _,line in stream['values']]
    return result,entries

assert git('branch','--show-current')=='feature/s2_scenario'
assert git('rev-parse','HEAD')==HEAD
assert git('status','--porcelain')==''
client=docker.from_env()
required=['grafana','loki','alertmanager','network-observer-zeek','network-observer-enricher','fluentd','leafy-backend','leafy-db','s2-sink-a']
state={n:client.containers.get(n).status for n in required+['aiops-pipeline','aiops-remediation']}
assert all(state[n]=='running' for n in required), state
assert all(state[n]=='exited' for n in ('aiops-pipeline','aiops-remediation')), state
policy=yaml.safe_load((ROOT/'aiops/policy/allowlist.yml').read_text(encoding='utf8'))
assert any(a.get('match')=='endpoint' and a.get('ip')=='10.210.0.30' and a.get('port')==8080 for a in policy['allow'])
assert any(n.get('IPAddress')=='10.210.0.30' for n in client.containers.get('s2-sink-a').attrs['NetworkSettings']['Networks'].values())
backend_ip=next(n['IPAddress'] for n in client.containers.get('leafy-backend').attrs['NetworkSettings']['Networks'].values() if n['IPAddress'].startswith('10.210.'))
runtime_config=yaml.safe_load(urllib.request.urlopen('http://localhost:3100/config').read())
ruler_config={k:runtime_config['ruler'][k] for k in ('evaluation_interval','notification_timeout','resend_delay','alertmanager_url')}
baseline_alerts=get('http://localhost:9093/api/v2/alerts')
baseline_rules=get('http://localhost:3100/prometheus/api/v1/rules')
interval=network_group(baseline_rules)['interval']
assert interval==60
wait_after_ingestion=2*interval+10+5
save('alertmanager-baseline.json',baseline_alerts)
save('ruler-baseline.json',baseline_rules)
save('dashboard-baseline.json',dashboard)
save('preflight.json',{'checked_at':now(),'branch':git('branch','--show-current'),'commit':HEAD,'containers':state,
                       'ruler_config':ruler_config,'rule_interval_seconds':interval,'post_ingestion_observation_seconds':wait_after_ingestion,
                       'backend_ip':backend_ip,'sink_ip':'10.210.0.30','sink_port':8080,'window_start_ms':window_start})
baseline_panels={str(i):panel_query(i) for i in (61,62,63,64,65,71,72,73,74)}
save('grafana-baseline.json',baseline_panels)

sys.path.insert(0,str(ROOT/'scenarios/network'))
import experiment
assert len(experiment.build_plan('V1',0,1))==1
assert experiment.build_plan('V1',0,1)[0].scenario=='C-a'
real_transfer=experiment.run_transfer
captured=[]
stop=threading.Event()
samples=[]
errors=[]
ingested=[]
run_start=time.time()

def monitor():
    while not stop.is_set():
        try:
            alerts=get('http://localhost:9093/api/v2/alerts')
            rules=get('http://localhost:3100/prometheus/api/v1/rules')
            logs,entries=network_logs(run_start)
            counts={kind:len([e for e in entries if e['event_type']==kind]) for kind in ('connection','connection_threshold')}
            if counts['connection']>=8 and counts['connection_threshold']>=8 and not ingested:
                ingested.append((time.monotonic(),now()))
            sample={'checked_at':now(),'alerts':alerts,'rule_group':network_group(rules),'log_counts':counts}
            samples.append(sample)
            with (OUT/'observations.jsonl').open('a',encoding='utf8') as fh:
                fh.write(json.dumps(sample,ensure_ascii=False)+'\n')
        except Exception as exc:
            errors.append({'checked_at':now(),'error':type(exc).__name__+': '+str(exc)})
        stop.wait(5)

def instrumented_transfer(run, *args, **kwargs):
    assert run.scenario=='C-a' and run.destination.ip=='10.210.0.30'
    assert len(captured)==0, 'Only one C-a transmission is authorized'
    started=now()
    result=real_transfer(run,*args,**kwargs)
    captured.append({'invoked_at':started,'completed_observed_at':now(),'result':result})
    save('transfer.json',captured[0])
    print('C-a transfer completed; crosscheck:',result['crosscheck']['ok'],flush=True)
    return result

experiment.run_transfer=instrumented_transfer
db_env=dict(x.split('=',1) for x in client.containers.get('leafy-db').attrs['Config']['Env'] if '=' in x)
os.environ['DB_PASSWORD']=db_env['POSTGRES_PASSWORD']
thread=threading.Thread(target=monitor,daemon=True)
thread.start()
print('Baseline saved. Existing alerts:',len(baseline_alerts),'Rule interval:',interval,flush=True)
try:
    code=experiment.main(['run','V1','--s2-reps','0','--ca-reps','1','--out-dir',str(OUT/'results')])
    assert code==0 and len(captured)==1
    deadline=time.monotonic()+180
    while (not ingested or time.monotonic()-ingested[0][0]<wait_after_ingestion) and time.monotonic()<deadline:
        time.sleep(2)
    assert ingested, 'Loki did not ingest both connection and threshold events'
    assert time.monotonic()-ingested[0][0]>=wait_after_ingestion, 'Observation window incomplete'
finally:
    stop.set()
    thread.join(timeout=30)
    save('observation-errors.json',errors)
assert not errors, errors
result_file=next((OUT/'results').glob('*_runs.jsonl'))
result_rows=[json.loads(l) for l in result_file.read_text(encoding='utf8').splitlines()]
assert len(result_rows)==1
record=result_rows[0]
assert record['scenario']=='C-a' and record['valid'] and not record['detected'] and record['outcome']=='TN'
assert record['mttd_seconds'] is None and record['detected_at'] is None
assert record['detection_status']=='not_detected'
assert captured[0]['result']['crosscheck']['ok']
assert captured[0]['result']['crosscheck']['total_bytes_sent']==10485760
assert captured[0]['result']['crosscheck']['total_bytes_received']==10485760
assert all(c['status']==200 and c['sha256']==c['sink_sha256'] for c in captured[0]['result']['sender_meta']['connections'])

logs,entries=network_logs(run_start)
save('loki-network-events.json',logs)
connections=[e for e in entries if e['event_type']=='connection']
thresholds=[e for e in entries if e['event_type']=='connection_threshold']
assert len(connections)==8 and len(thresholds)==8
assert all(e['src_ip']==backend_ip and e['dst_ip']=='10.210.0.30' and e['dst_port']==8080 for e in connections)
zeek=client.containers.get('network-observer-zeek')
raw_zeek={}
for filename in ('conn.log','conn_threshold.log'):
    response=zeek.exec_run(['cat','/zeek-logs/'+filename])
    assert response.exit_code==0
    raw_zeek[filename]=[json.loads(l) for l in response.output.decode().splitlines() if l.startswith('{')]
    raw_zeek[filename]=[e for e in raw_zeek[filename] if e.get('ts',0)>=run_start and e.get('id.orig_h')==backend_ip and e.get('id.resp_h')=='10.210.0.30' and e.get('id.resp_p')==8080]
assert len(raw_zeek['conn.log'])==8
assert {e['uid'] for e in raw_zeek['conn.log']}=={e['connection_id'] for e in connections}
save('zeek-connections.json',raw_zeek)
baseline_keys={identity(a) for a in baseline_alerts}
new_alerts={}
rule_evaluations=set()
for sample in samples:
    for a in sample['alerts']:
        if a['labels'].get('alertname') in NAMES and identity(a) not in baseline_keys:
            new_alerts[identity(a)]=a
    for r in sample['rule_group']['rules']:
        if r['name'] in NAMES:
            assert r['health']=='ok' and not r['lastError'],r
            # No new Sink A rule instance, even if an old Sink B instance existed.
            assert not any(a['labels'].get('dst_ip')=='10.210.0.30' for a in r['alerts']),r
    evaluated=sample['rule_group']['lastEvaluation']
    if datetime.fromisoformat(evaluated.replace('Z','+00:00'))>=datetime.fromisoformat(ingested[0][1]):
        rule_evaluations.add(evaluated)
assert len(rule_evaluations)>=2
assert not new_alerts, list(new_alerts.values())
final_alerts=get('http://localhost:9093/api/v2/alerts')
save('alertmanager-after.json',final_alerts)
save('ruler-after.json',get('http://localhost:3100/prometheus/api/v1/rules'))
after_panels={str(i):panel_query(i) for i in (61,62,63,64,65,71,72,73,74)}
save('grafana-after.json',after_panels)
assert numeric(after_panels['63'])==sum(e['bytes_sent'] for e in connections)
sink_series=[]
for frame in frames(after_panels['64']):
    for field,values in zip(frame['schema']['fields'],frame['data']['values']):
        if field.get('labels',{}).get('dst_ip')=='10.210.0.30' and field['type']=='number':
            sink_series.extend(v for v in values if v is not None)
assert sink_series and max(sink_series)>0, 'Panel 64 missing authorized destination series'
assert any('sink-a 10.210.0.30:8080' in r.get('Line','') for r in rows(after_panels['65']))
assert numeric(after_panels['71'])==numeric(baseline_panels['71'])
assert numeric(after_panels['71'],'B')==numeric(baseline_panels['71'],'B')
ca_only=panel_query(71,record['experiment_id'])
assert numeric(ca_only) is None and numeric(ca_only,'B')==0
save('grafana-mttd-ca-only.json',ca_only)
evaluation_rows=[json.loads(r['Line']) for r in rows(after_panels['72'])]
assert [r for r in evaluation_rows if r['experiment_id']==record['experiment_id']]==[record]
active=[a for a in final_alerts if a['labels'].get('alertname') in NAMES and a['labels'].get('category')=='security' and a['status']['state']=='active' and a['labels'].get('dst_ip') and a['labels'].get('dst_port')]
assert numeric(after_panels['73'])==len(active)
detail_rows=rows(after_panels['74'])
assert len(detail_rows)==len(active)
for a in active:
    row=next(r for r in detail_rows if r['fingerprint']==a['fingerprint'])
    assert row['경보 이름']==a['labels']['alertname'] and row['상태']==a['status']['state'] and row['시작 (UTC)']==a['startsAt']
    assert json.loads(row['labels'])==a['labels']
assert json.loads(dashboard_path.read_text(encoding='utf8'))==dashboard
assert grafana('/api/dashboards/uid/aiops-main')['dashboard']['panels']==dashboard['panels']
assert git('status','--porcelain')=='' and git('rev-parse','HEAD')==HEAD
assert all(client.containers.get(n).status=='exited' for n in ('aiops-pipeline','aiops-remediation'))
summary={'finished_at':now(),'experiment_id':record['experiment_id'],'record':record,
         'sender_started_at':captured[0]['result']['sender_meta']['sent_start_t0'],
         'transfer_completed_observed_at':captured[0]['completed_observed_at'],
         'backend_ip':backend_ip,'destination':'10.210.0.30:8080','payload_bytes':10485760,
         'zeek_connection_bytes':sum(e['bytes_sent'] for e in connections),
         'loki_connection_count':len(connections),'loki_threshold_count':len(thresholds),
         'baseline_alert_count':len(baseline_alerts),'final_alert_count':len(final_alerts),
         'new_network_alert_count':len(new_alerts),'observation_samples':len(samples),
         'first_all_events_ingested_at':ingested[0][1],'post_ingestion_observation_seconds':wait_after_ingestion,
         'completed_rule_evaluations':sorted(rule_evaluations),
         'mttd_before':numeric(baseline_panels['71']),'mttd_after':numeric(after_panels['71']),
         'mttd_sample_count_before':numeric(baseline_panels['71'],'B'),'mttd_sample_count_after':numeric(after_panels['71'],'B'),
         'active_panel_value':numeric(after_panels['73']),'original_panel_objects_unchanged':len(dashboard['panels']),
         'checks':{'transfer':True,'hashes':True,'zeek':True,'loki':True,'zero_new_network_alerts':True,
                   'grafana_transfer_bytes':True,'mttd_not_polluted':True,'evaluation_row':True,
                   'grafana_alerts_match_api':True,'no_panel_changes':True,'safety':True}}
save('summary.json',summary)
print(json.dumps(summary,ensure_ascii=False,indent=2),flush=True)
