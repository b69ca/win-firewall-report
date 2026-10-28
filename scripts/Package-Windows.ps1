$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force artifacts/publish,artifacts/dist | Out-Null
dotnet publish ./WinFirewallReport.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o artifacts/publish
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item README.md,LICENSE,CHANGELOG.md artifacts/publish
Compress-Archive -Path artifacts/publish/win-firewall-report.exe,artifacts/publish/README.md,artifacts/publish/LICENSE,artifacts/publish/CHANGELOG.md -DestinationPath artifacts/dist/win-firewall-report-1.0.0-win-x64.zip -Force
$hash = (Get-FileHash artifacts/dist/win-firewall-report-1.0.0-win-x64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  win-firewall-report-1.0.0-win-x64.zip" | Set-Content artifacts/dist/SHA256SUMS.txt -Encoding ascii
