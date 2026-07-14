using Microsoft.EntityFrameworkCore;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class EventSimulatorService : IEventSimulatorService
{
    private readonly ISecurityEventService _eventService;
    private readonly SecureWatchDbContext _context;
    private readonly DatabaseSeeder _seeder;

    public EventSimulatorService(
        ISecurityEventService eventService,
        SecureWatchDbContext context,
        DatabaseSeeder seeder)
    {
        _eventService = eventService;
        _context = context;
        _seeder = seeder;
    }

    public async Task<ApiResponse<string>> TriggerScenarioAsync(string scenarioType, CancellationToken ct = default)
    {
        switch (scenarioType.ToLowerInvariant())
        {
            case "normal-login":
                await SimulateNormalLoginAsync(ct);
                return ApiResponse<string>.Ok("Normal login event simulated successfully.");

            case "brute-force-fast":
                await SimulateBruteForceFastAsync(ct);
                return ApiResponse<string>.Ok("Rapid brute force attack scenario simulated (6 failed attempts generated).");

            case "brute-force-aggressive":
                await SimulateBruteForceAggressiveAsync(ct);
                return ApiResponse<string>.Ok("Aggressive brute force scenario simulated (21 rapid failed attempts generated).");

            case "credential-spray":
                await SimulateCredentialSprayAsync(ct);
                return ApiResponse<string>.Ok("Credential spray scenario simulated (4 distinct user accounts targeted from single IP).");

            case "malicious-ip":
                await SimulateMaliciousIpAsync(ct);
                return ApiResponse<string>.Ok("Malicious IP authentication probe simulated (known hostile botnet IP).");

            case "tor-proxy":
                await SimulateTorProxyAsync(ct);
                return ApiResponse<string>.Ok("Anonymized Tor exit node login simulated.");

            default:
                return ApiResponse<string>.Fail($"Unknown scenario type '{scenarioType}'. Supported: normal-login, brute-force-fast, brute-force-aggressive, credential-spray, malicious-ip, tor-proxy.");
        }
    }

    private async Task SimulateNormalLoginAsync(CancellationToken ct)
    {
        var usernames = new[] { "analyst@securewatch.local", "secadmin@securewatch.local", "user.marketing@securewatch.local" };
        var randomUser = usernames[Random.Shared.Next(usernames.Length)];

        await _eventService.IngestEventAsync(new CreateSecurityEventDto
        {
            EventType = "UserLoginSuccess",
            Category = EventCategory.SuccessfulLogin,
            Severity = SeverityLevel.Low,
            SourceIp = "10.0.0.15",
            Username = randomUser,
            DeviceInfo = "Windows 11 / Chrome 132",
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            Description = $"Routine successful user authentication for {randomUser}.",
            IsSimulated = true
        }, ct);
    }

    private async Task SimulateBruteForceFastAsync(CancellationToken ct)
    {
        var attackerIp = $"198.51.100.{Random.Shared.Next(10, 99)}";
        for (int i = 0; i < 6; i++)
        {
            await _eventService.IngestEventAsync(new CreateSecurityEventDto
            {
                EventType = "UserLoginFailed",
                Category = EventCategory.FailedLogin,
                Severity = SeverityLevel.Medium,
                SourceIp = attackerIp,
                Username = "admin@securewatch.local",
                DeviceInfo = "Linux / Hydra-v9.5",
                UserAgent = "Hydra/9.5 (Kali Linux)",
                Description = $"Failed login attempt #{i + 1} for target admin@securewatch.local (Invalid Password).",
                IsSimulated = true
            }, ct);
        }
    }

    private async Task SimulateBruteForceAggressiveAsync(CancellationToken ct)
    {
        var attackerIp = $"203.0.113.{Random.Shared.Next(100, 250)}";
        for (int i = 0; i < 22; i++)
        {
            await _eventService.IngestEventAsync(new CreateSecurityEventDto
            {
                EventType = "UserLoginFailed",
                Category = EventCategory.FailedLogin,
                Severity = SeverityLevel.High,
                SourceIp = attackerIp,
                Username = "root@securewatch.local",
                DeviceInfo = "Linux / Automated-Botnet",
                UserAgent = "Go-http-client/2.0",
                Description = $"Aggressive credential flooding attempt #{i + 1} for target root@securewatch.local.",
                IsSimulated = true
            }, ct);
        }
    }

    private async Task SimulateCredentialSprayAsync(CancellationToken ct)
    {
        var attackerIp = $"198.51.100.{Random.Shared.Next(150, 200)}";
        var targets = new[] { "alice@securewatch.local", "bob@securewatch.local", "charlie@securewatch.local", "david@securewatch.local" };

        foreach (var target in targets)
        {
            await _eventService.IngestEventAsync(new CreateSecurityEventDto
            {
                EventType = "UserLoginFailed",
                Category = EventCategory.FailedLogin,
                Severity = SeverityLevel.Medium,
                SourceIp = attackerIp,
                Username = target,
                DeviceInfo = "Windows / PowerShell-InvokeWebRequest",
                UserAgent = "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows PowerShell)",
                Description = $"Credential spray password guess attempted against user {target}.",
                IsSimulated = true
            }, ct);
        }
    }

    private async Task SimulateMaliciousIpAsync(CancellationToken ct)
    {
        await _eventService.IngestEventAsync(new CreateSecurityEventDto
        {
            EventType = "UserLoginFailed",
            Category = EventCategory.FailedLogin,
            Severity = SeverityLevel.Critical,
            SourceIp = "198.51.100.42", // Known hostile IP in seeded reputations
            Username = "finance.lead@securewatch.local",
            DeviceInfo = "Linux / Tor-Exit-Relay",
            UserAgent = "python-requests/2.31.0",
            Description = "Authentication failure originating from confirmed Eastern Europe botnet node 198.51.100.42.",
            IsSimulated = true
        }, ct);
    }

    private async Task SimulateTorProxyAsync(CancellationToken ct)
    {
        await _eventService.IngestEventAsync(new CreateSecurityEventDto
        {
            EventType = "UserLoginSuccess",
            Category = EventCategory.SuccessfulLogin,
            Severity = SeverityLevel.High,
            SourceIp = "185.220.101.5", // Known Tor exit node
            Username = "remote.contractor@securewatch.local",
            DeviceInfo = "TorBrowser 13.0 / Linux",
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            Description = "Privileged user login routed via verified Tor exit node in Frankfurt, Germany.",
            IsSimulated = true
        }, ct);
    }

    public async Task<ApiResponse<bool>> ResetDemoDataAsync(CancellationToken ct = default)
    {
        // Delete simulated events, threats, incidents, and alerts
        var simAlerts = await _context.Alerts.Where(a => a.Incident != null && a.Incident.IsSimulated).ToListAsync(ct);
        _context.Alerts.RemoveRange(simAlerts);

        var simIncidentEvents = await _context.IncidentEvents.Where(ie => ie.Incident.IsSimulated).ToListAsync(ct);
        _context.IncidentEvents.RemoveRange(simIncidentEvents);

        var simNotes = await _context.IncidentNotes.Where(n => n.Incident.IsSimulated).ToListAsync(ct);
        _context.IncidentNotes.RemoveRange(simNotes);

        var simIncidents = await _context.Incidents.Where(i => i.IsSimulated).ToListAsync(ct);
        _context.Incidents.RemoveRange(simIncidents);

        var simThreats = await _context.ThreatDetections.Where(t => t.IsSimulated).ToListAsync(ct);
        _context.ThreatDetections.RemoveRange(simThreats);

        var simEvents = await _context.SecurityEvents.Where(e => e.IsSimulated).ToListAsync(ct);
        _context.SecurityEvents.RemoveRange(simEvents);

        await _context.SaveChangesAsync(ct);

        // Re-seed baseline demo data
        await _seeder.SeedAsync();

        return ApiResponse<bool>.Ok(true, "Demo environment successfully reset to pristine baseline state.");
    }
}

