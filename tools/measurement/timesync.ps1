# Windows 시각과 WSL(docker-desktop)·컨테이너·Prometheus 시각 차이를 잰다. 결과를 한 줄 JSON 으로 -Out 에 덧붙인다.
#   powershell -File timesync.ps1 -Label start -Out <run dir>\timesync.jsonl
param([string]$Label, [string]$Out, [string]$Prom = 'http://127.0.0.1:9090')

function WinEpoch { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0 }
function Probe([scriptblock]$get) {
    $t0 = WinEpoch; $v = & $get; $t1 = WinEpoch
    if ($null -eq $v -or "$v" -eq '') { return $null }
    # 왕복 시간의 중간 시각과 비교한다
    return [math]::Round([double]$v - (($t0 + $t1) / 2), 3)
}

$row = [ordered]@{ label = $Label; windows_utc = [DateTimeOffset]::UtcNow.ToString('o') }
$row.wsl_docker_desktop_sec = Probe { (wsl.exe -d docker-desktop date +%s.%N 2>$null) }
$row.container_ollama_sec   = Probe { (docker exec ollama date +%s.%N 2>$null) }
$row.container_backend_sec  = Probe { (docker exec leafy-backend date +%s 2>$null) }   # busybox: 초 단위
$row.prometheus_time_sec    = Probe { (Invoke-RestMethod "$Prom/api/v1/query?query=time()").data.result[1] }
($row | ConvertTo-Json -Compress) | Add-Content -Encoding utf8 $Out
$row | ConvertTo-Json
