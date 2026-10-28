# win-firewall-report

Read-only Windows firewall profile review for support engineers. It checks the Domain, Private and Public profile states, default inbound/outbound actions, and blocked-connection logging. It reports observations and review prompts; it does not inspect every firewall rule or prove why a connection failed.

## Requirements and installation

Use Windows 10/11 or Windows Server with Windows PowerShell 5.1 and `Get-NetFirewallProfile` for live collection. Download the `win-x64` ZIP from Releases, verify its SHA-256 against `SHA256SUMS.txt`, extract it, and run `win-firewall-report.exe`. The executable is self-contained and unsigned. Building from source requires .NET SDK 9.

## Examples

```powershell
./win-firewall-report.exe
./win-firewall-report.exe --json
./win-firewall-report.exe --from snapshot.json --json
./win-firewall-report.exe --help
```

To save a snapshot for offline review, run `./win-firewall-report.exe --json` and retain only the `Snapshot` object from the output as `snapshot.json`. Protect it as local configuration data. Offline replay is available on any platform with the matching .NET runtime or standalone build.

## Options and exit codes

- `--json`: structured report with `Snapshot`, `Findings`, and `Status`.
- `--from FILE`: analyze a previously saved version 1 snapshot without live collection. File limit: 1 MiB.
- `--help`: usage.
- Exit 0: full evidence, no review prompts. Exit 2: full evidence with review prompts. Exit 3: partial evidence. Exit 1: invalid input or local failure.

`firewall-disabled` and `inbound-allow` indicate profile settings that merit review. `blocked-logging-off` means blocked traffic will not be logged by that profile. A setting may be intentional policy. `partial` means at least one profile or important field is unavailable; it is never reported as healthy. The tool never changes a setting.

## Privacy and limits

The report contains profile names and policy settings only. It does not collect rules, application paths, addresses, account names, firewall logs, or packet data. Snapshot files can still reveal security posture; store them appropriately. Collection uses a fixed PowerShell command with a 30-second timeout. PowerShell availability and permissions affect coverage. The three profiles are only the effective profile summary visible to the current account. Rules, group policy precedence, third-party firewalls, network classification, and active traffic are outside scope. A review prompt is an observation, not a root-cause claim.

## Troubleshooting

If collection is partial, run in a Windows session with `Get-NetFirewallProfile` available and inspect whether the Windows firewall service or policy provider is accessible. The tool does not require administrator rights for ordinary profile reads, but policy can limit access. Use `--from` for saved snapshots when live collection is unavailable. To build and test locally, run `pwsh ./scripts/Validate.ps1`, or `dotnet build -c Release` and `dotnet run --project tests/Tests.csproj -c Release`.
