$ErrorActionPreference = 'Stop'
dotnet build ./WinFirewallReport.csproj -c Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet run --project ./tests/Tests.csproj -c Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet run --project ./WinFirewallReport.csproj -c Release -- --help
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
