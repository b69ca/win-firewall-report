using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinFirewallReport;

public sealed record Profile(string Name, bool? Enabled, string? DefaultInboundAction,
    string? DefaultOutboundAction, bool? LogBlocked);
public sealed record Snapshot(int SchemaVersion, DateTimeOffset CapturedAt, string Source,
    List<Profile> Profiles, string? Error);
public sealed record Finding(string Profile, string Code, string Detail);
public sealed record Report(Snapshot Snapshot, List<Finding> Findings, string Status);

public static class App
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static int Main(string[] args)
    {
        try
        {
            if (args.Contains("--help"))
            {
                if (args.Length != 1) throw new ArgumentException("--help must be used alone");
                Console.WriteLine("win-firewall-report [--json] [--from SNAPSHOT.json]");
                Console.WriteLine("Read Windows firewall profile policy without changing it. --from analyzes a saved snapshot offline.");
                return 0;
            }
            bool json = false;
            string? from = null;
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--json": if (json) throw new ArgumentException("duplicate --json"); json = true; break;
                    case "--from":
                        if (from is not null || ++i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                            throw new ArgumentException("--from requires one file");
                        from = args[i]; break;
                    default: throw new ArgumentException($"unknown option: {args[i]}");
                }
            }
            Snapshot snapshot = from is null ? Collect() : Load(from);
            Report report = Analyze(snapshot);
            if (json) Console.WriteLine(JsonSerializer.Serialize(report, JsonOptions));
            else Print(report);
            return report.Status switch { "partial" => 3, "review" => 2, _ => 0 };
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or JsonException)
        {
            Console.Error.WriteLine($"win-firewall-report: {ex.Message}");
            return 1;
        }
    }

    public static Snapshot Load(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length > 1_048_576) throw new IOException("snapshot missing or exceeds 1 MiB");
        var snapshot = JsonSerializer.Deserialize<Snapshot>(File.ReadAllText(path, new UTF8Encoding(false, true)), JsonOptions)
            ?? throw new JsonException("empty snapshot");
        Validate(snapshot);
        return snapshot;
    }

    public static void Validate(Snapshot snapshot)
    {
        if (snapshot.SchemaVersion != 1 || snapshot.CapturedAt == default ||
            snapshot.Source is not ("windows" or "fixture") || snapshot.Profiles is null ||
            snapshot.Profiles.Count > 3 || snapshot.Error is { Length: > 256 })
            throw new JsonException("invalid snapshot schema");
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in snapshot.Profiles)
        {
            if (p is null || p.Name is not ("Domain" or "Private" or "Public") || !names.Add(p.Name) ||
                !ValidAction(p.DefaultInboundAction) || !ValidAction(p.DefaultOutboundAction))
                throw new JsonException("invalid firewall profile");
        }
    }

    private static bool ValidAction(string? action) => action is null or "Allow" or "Block" or "NotConfigured";

    public static Report Analyze(Snapshot snapshot)
    {
        Validate(snapshot);
        var findings = new List<Finding>();
        foreach (var p in snapshot.Profiles)
        {
            if (p.Enabled == false) findings.Add(new(p.Name, "firewall-disabled", "Firewall is disabled for this profile."));
            if (p.DefaultInboundAction == "Allow") findings.Add(new(p.Name, "inbound-allow", "Default inbound action allows connections."));
            if (p.LogBlocked == false) findings.Add(new(p.Name, "blocked-logging-off", "Blocked connection logging is disabled."));
        }
        bool partial = snapshot.Error is not null || snapshot.Profiles.Count != 3 ||
            snapshot.Profiles.Any(p => p.Enabled is null || p.DefaultInboundAction is null || p.DefaultOutboundAction is null);
        return new(snapshot, findings, partial ? "partial" : findings.Count > 0 ? "review" : "observed");
    }

    private static void Print(Report report)
    {
        Console.WriteLine($"Firewall profiles: {report.Status} ({report.Snapshot.CapturedAt:O})");
        foreach (var p in report.Snapshot.Profiles)
            Console.WriteLine($"{p.Name}: enabled={Value(p.Enabled)} inbound={p.DefaultInboundAction ?? "unknown"} outbound={p.DefaultOutboundAction ?? "unknown"} blocked-log={Value(p.LogBlocked)}");
        foreach (var f in report.Findings) Console.WriteLine($"REVIEW {f.Profile} {f.Code}: {f.Detail}");
        if (report.Status == "partial") Console.WriteLine("Coverage incomplete; missing evidence is not a healthy result.");
        if (report.Snapshot.Error is not null) Console.WriteLine($"Collection: {report.Snapshot.Error}");
    }
    private static string Value(bool? value) => value is null ? "unknown" : value.Value ? "on" : "off";

    private static Snapshot Collect()
    {
        if (!OperatingSystem.IsWindows()) throw new ArgumentException("live collection requires Windows; use --from for offline analysis");
        const string script = "$ErrorActionPreference='Stop'; try { $p=@(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Enabled=$(if ([string]$_.Enabled -eq 'True') { $true } elseif ([string]$_.Enabled -eq 'False') { $false } else { $null }); DefaultInboundAction=[string]$_.DefaultInboundAction; DefaultOutboundAction=[string]$_.DefaultOutboundAction; LogBlocked=$(if ([string]$_.LogBlocked -eq 'True') { $true } elseif ([string]$_.LogBlocked -eq 'False') { $false } else { $null }) } }); [pscustomobject]@{ SchemaVersion=1; CapturedAt=([DateTimeOffset]::UtcNow.ToString('o')); Source='windows'; Profiles=$p; Error=$null } | ConvertTo-Json -Depth 4 -Compress } catch { [pscustomobject]@{ SchemaVersion=1; CapturedAt=([DateTimeOffset]::UtcNow.ToString('o')); Source='windows'; Profiles=@(); Error='Firewall profile collection unavailable' } | ConvertTo-Json -Depth 4 -Compress }";
        using var process = new Process { StartInfo = new ProcessStartInfo("powershell.exe") {
            Arguments = "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)),
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };
        try { process.Start(); }
        catch (System.ComponentModel.Win32Exception) { return new(1, DateTimeOffset.UtcNow, "windows", [], "PowerShell unavailable"); }
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30000)) { process.Kill(entireProcessTree: true); return new(1, DateTimeOffset.UtcNow, "windows", [], "Collection timed out"); }
        string result = output.GetAwaiter().GetResult();
        _ = error.GetAwaiter().GetResult();
        if (process.ExitCode != 0 || result.Length > 1_048_576) return new(1, DateTimeOffset.UtcNow, "windows", [], "Collection failed");
        try { var snapshot = JsonSerializer.Deserialize<Snapshot>(result, JsonOptions)!; Validate(snapshot); return snapshot; }
        catch (JsonException) { return new(1, DateTimeOffset.UtcNow, "windows", [], "Collector returned invalid data"); }
    }
}
