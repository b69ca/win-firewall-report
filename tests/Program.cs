using System.Text.Json;
using WinFirewallReport;

int passed = 0;
void Check(bool condition, string label) { if (!condition) throw new Exception(label); passed++; }
Profile[] baseline = [new("Domain", true, "Block", "Allow", true), new("Private", true, "Block", "Allow", true), new("Public", true, "Block", "Allow", true)];
Snapshot Make(params Profile[] profiles) => new(1, DateTimeOffset.Parse("2026-01-01T00:00:00Z"), "fixture", profiles.ToList(), null);
Check(App.Analyze(Make(baseline)).Status == "observed", "baseline");
Check(App.Analyze(Make(baseline[0] with { Enabled = false }, baseline[1], baseline[2])).Findings.Any(x => x.Code == "firewall-disabled"), "disabled");
Check(App.Analyze(Make(baseline[0], baseline[1] with { DefaultInboundAction = "Allow" }, baseline[2])).Findings.Any(x => x.Code == "inbound-allow"), "allow inbound");
Check(App.Analyze(Make(baseline[0], baseline[1], baseline[2] with { LogBlocked = false })).Findings.Any(x => x.Code == "blocked-logging-off"), "logging");
Check(App.Analyze(Make(baseline[0])).Status == "partial", "missing profiles");
Check(App.Analyze(Make(baseline[0] with { Enabled = null }, baseline[1], baseline[2])).Status == "partial", "unknown enabled");
Check(App.Analyze(Make(baseline) with { Error = "unavailable" }).Status == "partial", "collection error");
try { App.Validate(Make(baseline[0], baseline[0])); throw new Exception("duplicate accepted"); } catch (JsonException) { passed++; }
try { App.Validate(Make(baseline[0] with { Name = "Bogus" })); throw new Exception("bad profile accepted"); } catch (JsonException) { passed++; }
try { App.Validate(Make(baseline[0] with { DefaultInboundAction = "Bogus" })); throw new Exception("bad action accepted"); } catch (JsonException) { passed++; }
string temp = Path.GetTempFileName();
try { File.WriteAllText(temp, JsonSerializer.Serialize(Make(baseline))); Check(App.Load(temp).Profiles.Count == 3, "offline load"); File.WriteAllText(temp, "{}"); try { App.Load(temp); throw new Exception("bad schema accepted"); } catch (JsonException) { passed++; } }
finally { File.Delete(temp); }
Console.WriteLine($"{passed} behavior checks passed");
