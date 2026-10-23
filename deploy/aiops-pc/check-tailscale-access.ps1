# JH(AIOps PC)에 적용된 Tailscale 패킷 필터에서 GC가 수집 포트(24224/24225)로 들어올 수 있는지 확인한다.
# GC와 JH는 서로 다른 tailnet이라, JH 장치를 GC 계정에 공유해야 GC가 먼저 연결할 수 있다 (Tailscale quarantine).
#   사용: powershell -ExecutionPolicy Bypass -File deploy\aiops-pc\check-tailscale-access.ps1 -GcIp <GC Tailscale IP>
#   정상: 두 포트 모두 ALLOWED.  BLOCKED면 docs/remote/REMOTE_DEPLOYMENT.md §3 (공유·ACL)
# 패킷 필터만 본다. 실제 연결은 JH가 AIOps(또는 리스너)를 띄운 상태에서 GC의 Test-NetConnection으로 확인한다.
param([Parameter(Mandatory)][string]$GcIp, [int[]]$Ports = @(24224, 24225))

function Test-InCidr([string]$Ip, [string]$Cidr) {
  $net, $len = $Cidr -split '/'
  if ($net -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $false }   # IPv6 규칙은 건너뛴다
  $len = if ($len) { [int]$len } else { 32 }
  $a = [BitConverter]::ToUInt32([byte[]]([Net.IPAddress]::Parse($Ip).GetAddressBytes()[3..0]), 0)
  $b = [BitConverter]::ToUInt32([byte[]]([Net.IPAddress]::Parse($net).GetAddressBytes()[3..0]), 0)
  # PowerShell 5.1에서 0xFFFFFFFF 리터럴은 Int32 -1이 되므로 10진수로 쓴다
  $all = [uint64]4294967295
  $mask = if ($len -eq 0) { [uint64]0 } else { ($all -shl (32 - $len)) -band $all }
  return (([uint64]$a -band $mask) -eq ([uint64]$b -band $mask))
}

$tailscale = (Get-Command tailscale -ErrorAction SilentlyContinue).Source
if (-not $tailscale) { $tailscale = "C:\Program Files\Tailscale\tailscale.exe" }
# tailscale은 UTF-8로 출력한다. 콘솔 기본(cp949)으로 읽으면 JSON이 깨지므로 잠시 바꾼다
$prevEncoding = [Console]::OutputEncoding
[Console]::OutputEncoding = [Text.Encoding]::UTF8
try { $nm = (& $tailscale debug netmap | Out-String) | ConvertFrom-Json } finally { [Console]::OutputEncoding = $prevEncoding }
foreach ($port in $Ports) {
  $allowed = $false
  foreach ($rule in $nm.PacketFilter) {
    $srcs = @($rule.Srcs) + @($rule.SrcIPs) | Where-Object { $_ }
    $portOk = @($rule.Dsts | Where-Object { $_.Ports.First -le $port -and $_.Ports.Last -ge $port }).Count -gt 0
    if ($portOk -and @($srcs | Where-Object { $_ -eq '*' -or (Test-InCidr $GcIp $_) }).Count -gt 0) { $allowed = $true }
  }
  "{0} -> this PC:{1}  {2}" -f $GcIp, $port, $(if ($allowed) { "ALLOWED" } else { "BLOCKED (share JH machine with GC account / check JH tailnet ACL)" })
}
