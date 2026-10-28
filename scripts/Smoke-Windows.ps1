param([string]$Executable = './artifacts/publish/win-firewall-report.exe')
$ErrorActionPreference = 'Stop'
$raw = & $Executable --json
if ($LASTEXITCODE -notin @(0,2,3)) { throw 'live collection failed' }
$report = $raw | ConvertFrom-Json
if ($report.Snapshot.Source -ne 'windows') { throw 'wrong source' }
if ($report.Snapshot.Profiles.Count -ne 3) { throw 'expected three firewall profiles' }
$expected = @('Domain','Private','Public')
foreach ($p in $report.Snapshot.Profiles) { if ($p.Name -notin $expected) { throw 'unexpected profile name' } }
if ($report.Status -eq 'partial') { throw 'live profile evidence unavailable' }
$temp = Join-Path $env:TEMP ([guid]::NewGuid().ToString() + '.json')
try {
  $report.Snapshot | ConvertTo-Json -Depth 4 | Set-Content $temp -Encoding UTF8
  $replay = & $Executable --from $temp --json
  if ($LASTEXITCODE -notin @(0,2)) { throw 'replay failed' }
  $again = $replay | ConvertFrom-Json
  if ($again.Findings.Count -ne $report.Findings.Count) { throw 'replay findings differ' }
} finally { Remove-Item $temp -ErrorAction SilentlyContinue }
Write-Output 'Windows live collection and replay passed'
