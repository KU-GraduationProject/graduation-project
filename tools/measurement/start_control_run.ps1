# 대조 이벤트 실행: NotBefore 시각까지 기다린 뒤 timesync → 경보 기록기 → 트래픽 생성기(대조 모드)를
# Win32_Process.Create 로 띄운다(Claude 세션이 끝나도 계속 돈다).
param([string]$Run, [datetime]$NotBefore, [string]$Plan, [int]$Seed, [int]$Duration,
      [string]$Base = 'http://127.0.0.1', [string]$Tools = $PSScriptRoot)
# $Base: 트래픽을 보낼 프론트 URL(예: Tailscale IP). $Tools: 측정 도구 폴더(기본=이 스크립트 폴더).
$tools = $Tools
while ((Get-Date) -lt $NotBefore) { Start-Sleep 5 }
Set-Location $Run
powershell -NoProfile -ExecutionPolicy Bypass -File "$tools\timesync.ps1" -Label start -Out "$Run\timesync.jsonl" | Out-Null
$py = (Get-Command python).Source
$rec = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = "cmd.exe /c `"`"$py`" -I `"$tools\alert_recorder.py`" --out `"$Run\alerts.jsonl`" --interval 15 2> `"$Run\alert_recorder.err`"`""
    CurrentDirectory = $Run }
$start = Get-Date
$tg = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = "cmd.exe /c `"`"$py`" -I `"$tools\traffic_gen.py`" --base $Base --dir `"$Run`" --duration $Duration --seed $Seed --control mixed --control-plan $Plan 2> `"$Run\traffic_gen.err`"`""
    CurrentDirectory = $Run }
"measure_start=$($start.ToString('o')) planned_end=$($start.AddSeconds($Duration).ToString('o')) rec_rv=$($rec.ReturnValue) tg_rv=$($tg.ReturnValue) seed=$Seed plan=$Plan" |
    Add-Content -Encoding utf8 "$Run\timeline.txt"
Start-Sleep 20
"rec_pid=$(Get-Content "$Run\alerts.jsonl.pid") tg_pid=$(Get-Content "$Run\traffic_gen.pid") requests_after_20s=$((Get-Content "$Run\requests.jsonl").Count)" |
    Add-Content -Encoding utf8 "$Run\timeline.txt"
Get-Content "$Run\timeline.txt" -Tail 2
