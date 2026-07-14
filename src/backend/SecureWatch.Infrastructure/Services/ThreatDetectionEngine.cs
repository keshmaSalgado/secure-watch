using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Entities;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class ThreatDetectionEngine : IThreatDetectionEngine
{
    private readonly SecureWatchDbContext _context;
    private readonly IIpReputationService _ipReputationService;
    private readonly ISecurityHubService _securityHubService;
    private readonly ILogger<ThreatDetectionEngine> _logger;

    public ThreatDetectionEngine(
        SecureWatchDbContext context,
        IIpReputationService ipReputationService,
        ISecurityHubService securityHubService,
        ILogger<ThreatDetectionEngine> logger)
    {
        _context = context;
        _ipReputationService = ipReputationService;
        _securityHubService = securityHubService;
        _logger = logger;
    }

    public async Task<List<ThreatDetection>> EvaluateEventAsync(SecurityEvent securityEvent, CancellationToken ct = default)
    {
        var detections = new List<ThreatDetection>();
        var activeRules = await _context.SecurityRules
            .AsNoTracking()
            .Where(r => r.IsEnabled)
            .ToListAsync(ct);

        var eventTime = securityEvent.EventTimestampUtc;

        // Rule 01: 5 failed logins within 1 minute
        var rule01 = activeRules.FirstOrDefault(r => r.Code == "RULE-01-BRUTE-FAST");
        if (rule01 != null && securityEvent.Category == EventCategory.FailedLogin)
        {
            var windowStart = eventTime.AddSeconds(-rule01.TimeWindowSeconds);
            var failuresInWindow = await _context.SecurityEvents
                .AsNoTracking()
                .Where(e => e.SourceIp == securityEvent.SourceIp &&
                            e.Category == EventCategory.FailedLogin &&
                            e.EventTimestampUtc >= windowStart &&
                            e.EventTimestampUtc <= eventTime)
                .ToListAsync(ct);

            var count = failuresInWindow.Count + 1; // including current event
            if (count >= rule01.ThresholdCount)
            {
                var evidenceIds = failuresInWindow.Select(e => e.Id).ToList();
                evidenceIds.Add(securityEvent.Id);

                var riskScore = Math.Min(100, rule01.BaseRiskScore + (count - rule01.ThresholdCount) * 2);
                detections.Add(new ThreatDetection
                {
                    RuleId = rule01.Id,
                    RuleName = rule01.Name,
                    ThreatType = ThreatType.BruteForce,
                    DetectionReason = $"Detected {count} authentication failures within {rule01.TimeWindowSeconds}s window from source IP {securityEvent.SourceIp}.",
                    Severity = SeverityLevel.High,
                    RiskScore = riskScore,
                    SourceIp = securityEvent.SourceIp,
                    TargetedUsername = securityEvent.Username,
                    DetectedAtUtc = DateTime.UtcNow,
                    EvidenceEventIdsJson = JsonSerializer.Serialize(evidenceIds),
                    RecommendedActions = "1. Enforce rate limiting or temporary IP ban.\n2. Verify target account MFA.\n3. Check for coordinated multi-IP activity.",
                    IsSimulated = securityEvent.IsSimulated
                });
            }
        }

        // Rule 02: 20 failed logins within 2 minutes (Aggressive Brute Force)
        var rule02 = activeRules.FirstOrDefault(r => r.Code == "RULE-02-BRUTE-AGGRESSIVE");
        if (rule02 != null && securityEvent.Category == EventCategory.FailedLogin)
        {
            var windowStart = eventTime.AddSeconds(-rule02.TimeWindowSeconds);
            var failuresInWindow = await _context.SecurityEvents
                .AsNoTracking()
                .Where(e => e.SourceIp == securityEvent.SourceIp &&
                            e.Category == EventCategory.FailedLogin &&
                            e.EventTimestampUtc >= windowStart &&
                            e.EventTimestampUtc <= eventTime)
                .ToListAsync(ct);

            var count = failuresInWindow.Count + 1;
            if (count >= rule02.ThresholdCount)
            {
                var evidenceIds = failuresInWindow.Select(e => e.Id).ToList();
                evidenceIds.Add(securityEvent.Id);

                var riskScore = Math.Min(100, rule02.BaseRiskScore + (count - rule02.ThresholdCount));
                detections.Add(new ThreatDetection
                {
                    RuleId = rule02.Id,
                    RuleName = rule02.Name,
                    ThreatType = ThreatType.RapidFailures,
                    DetectionReason = $"Aggressive automated credential spray: {count} failed logins within {rule02.TimeWindowSeconds}s from IP {securityEvent.SourceIp}.",
                    Severity = SeverityLevel.Critical,
                    RiskScore = riskScore,
                    SourceIp = securityEvent.SourceIp,
                    TargetedUsername = securityEvent.Username,
                    DetectedAtUtc = DateTime.UtcNow,
                    EvidenceEventIdsJson = JsonSerializer.Serialize(evidenceIds),
                    RecommendedActions = "1. Immediate boundary firewall drop for IP.\n2. Review WAF logs.\n3. Inspect targeted user account lockouts.",
                    IsSimulated = securityEvent.IsSimulated
                });
            }
        }

        // Rule 03: Successful login immediately following repeated failures
        var rule03 = activeRules.FirstOrDefault(r => r.Code == "RULE-03-SUCCESS-AFTER-FAIL");
        if (rule03 != null && securityEvent.Category == EventCategory.SuccessfulLogin && !string.IsNullOrEmpty(securityEvent.Username))
        {
            var windowStart = eventTime.AddSeconds(-rule03.TimeWindowSeconds);
            var priorFailures = await _context.SecurityEvents
                .AsNoTracking()
                .Where(e => (e.Username == securityEvent.Username || e.SourceIp == securityEvent.SourceIp) &&
                            e.Category == EventCategory.FailedLogin &&
                            e.EventTimestampUtc >= windowStart &&
                            e.EventTimestampUtc <= eventTime)
                .ToListAsync(ct);

            if (priorFailures.Count >= rule03.ThresholdCount)
            {
                var evidenceIds = priorFailures.Select(e => e.Id).ToList();
                evidenceIds.Add(securityEvent.Id);

                detections.Add(new ThreatDetection
                {
                    RuleId = rule03.Id,
                    RuleName = rule03.Name,
                    ThreatType = ThreatType.SuccessAfterFailures,
                    DetectionReason = $"Potential account compromise: Successful login for '{securityEvent.Username}' immediately following {priorFailures.Count} failed attempts within {rule03.TimeWindowSeconds}s.",
                    Severity = SeverityLevel.High,
                    RiskScore = rule03.BaseRiskScore,
                    SourceIp = securityEvent.SourceIp,
                    TargetedUsername = securityEvent.Username,
                    DetectedAtUtc = DateTime.UtcNow,
                    EvidenceEventIdsJson = JsonSerializer.Serialize(evidenceIds),
                    RecommendedActions = "1. Contact account owner out-of-band to confirm login authorization.\n2. Force credential reset and revoke existing sessions if unverified.",
                    IsSimulated = securityEvent.IsSimulated
                });
            }
        }

        // Rule 04: Multiple accounts accessed from one IP address (Credential Spray)
        var rule04 = activeRules.FirstOrDefault(r => r.Code == "RULE-04-MULTI-ACCOUNT-SPRAY");
        if (rule04 != null && !string.IsNullOrEmpty(securityEvent.Username))
        {
            var windowStart = eventTime.AddSeconds(-rule04.TimeWindowSeconds);
            var targetUsersInWindow = await _context.SecurityEvents
                .AsNoTracking()
                .Where(e => e.SourceIp == securityEvent.SourceIp &&
                            !string.IsNullOrEmpty(e.Username) &&
                            e.EventTimestampUtc >= windowStart &&
                            e.EventTimestampUtc <= eventTime)
                .Select(e => e.Username!)
                .Distinct()
                .ToListAsync(ct);

            if (!targetUsersInWindow.Contains(securityEvent.Username))
            {
                targetUsersInWindow.Add(securityEvent.Username);
            }

            if (targetUsersInWindow.Count >= rule04.ThresholdCount)
            {
                detections.Add(new ThreatDetection
                {
                    RuleId = rule04.Id,
                    RuleName = rule04.Name,
                    ThreatType = ThreatType.MultiAccountTargeting,
                    DetectionReason = $"Credential spray pattern detected: IP {securityEvent.SourceIp} targeted {targetUsersInWindow.Count} distinct accounts ({string.Join(", ", targetUsersInWindow.Take(4))}) within {rule04.TimeWindowSeconds}s.",
                    Severity = SeverityLevel.High,
                    RiskScore = rule04.BaseRiskScore,
                    SourceIp = securityEvent.SourceIp,
                    TargetedUsername = securityEvent.Username,
                    DetectedAtUtc = DateTime.UtcNow,
                    EvidenceEventIdsJson = JsonSerializer.Serialize(new List<Guid> { securityEvent.Id }),
                    RecommendedActions = "1. Block source IP at gateway.\n2. Audit all targeted user accounts for unauthorized modifications.",
                    IsSimulated = securityEvent.IsSimulated
                });
            }
        }

        // Rule 05: Login from known malicious IP
        var rule05 = activeRules.FirstOrDefault(r => r.Code == "RULE-05-MALICIOUS-IP");
        if (rule05 != null)
        {
            var ipRep = await _ipReputationService.GetReputationAsync(securityEvent.SourceIp, ct);
            if (ipRep.Success && ipRep.Data != null && (ipRep.Data.IsMalicious || ipRep.Data.ReputationScore >= 80))
            {
                var riskScore = Math.Max(rule05.BaseRiskScore, ipRep.Data.ReputationScore);
                detections.Add(new ThreatDetection
                {
                    RuleId = rule05.Id,
                    RuleName = rule05.Name,
                    ThreatType = ThreatType.MaliciousIpActivity,
                    DetectionReason = $"Activity observed from known hostile IP {securityEvent.SourceIp} (Reputation Score: {ipRep.Data.ReputationScore}/100, ISP: {ipRep.Data.Isp}, Country: {ipRep.Data.CountryName}).",
                    Severity = SeverityLevel.Critical,
                    RiskScore = riskScore,
                    SourceIp = securityEvent.SourceIp,
                    TargetedUsername = securityEvent.Username,
                    DetectedAtUtc = DateTime.UtcNow,
                    EvidenceEventIdsJson = JsonSerializer.Serialize(new List<Guid> { securityEvent.Id }),
                    RecommendedActions = "1. Immediate IP block in ingress ACL.\n2. Threat hunt for lateral movement.\n3. Validate session cookies if login was successful.",
                    IsSimulated = securityEvent.IsSimulated
                });
            }
        }

        // Rule 06: Unusual login time compared with established activity
        var rule06 = activeRules.FirstOrDefault(r => r.Code == "RULE-06-UNUSUAL-TIME");
        if (rule06 != null && securityEvent.Category == EventCategory.SuccessfulLogin)
        {
            var hour = eventTime.Hour; // UTC hour
            // Off-peak hours between 01:00 and 04:59 UTC
            if (hour >= 1 && hour <= 4)
            {
                detections.Add(new ThreatDetection
                {
                    RuleId = rule06.Id,
                    RuleName = rule06.Name,
                    ThreatType = ThreatType.UnusualLoginTime,
                    DetectionReason = $"Unusual off-hours access: Successful authentication recorded at {eventTime:HH:mm} UTC outside standard operational windows.",
                    Severity = SeverityLevel.Medium,
                    RiskScore = rule06.BaseRiskScore,
                    SourceIp = securityEvent.SourceIp,
                    TargetedUsername = securityEvent.Username,
                    DetectedAtUtc = DateTime.UtcNow,
                    EvidenceEventIdsJson = JsonSerializer.Serialize(new List<Guid> { securityEvent.Id }),
                    RecommendedActions = "1. Cross-reference against on-call shift rosters.\n2. Request analyst follow-up verification.",
                    IsSimulated = securityEvent.IsSimulated
                });
            }
        }

        // Rule 07: Multiple login attempts from unfamiliar locations / Tor / Proxy
        var rule07 = activeRules.FirstOrDefault(r => r.Code == "RULE-07-GEO-ANOMALY");
        if (rule07 != null)
        {
            var ipRep = await _ipReputationService.GetReputationAsync(securityEvent.SourceIp, ct);
            if (ipRep.Success && ipRep.Data != null && (ipRep.Data.IsTor || ipRep.Data.IsVpnOrProxy))
            {
                detections.Add(new ThreatDetection
                {
                    RuleId = rule07.Id,
                    RuleName = rule07.Name,
                    ThreatType = ThreatType.UnfamiliarLocation,
                    DetectionReason = $"Access attempt routed through anonymization infrastructure: Tor/Proxy detected ({ipRep.Data.Isp}, {ipRep.Data.CountryName}).",
                    Severity = SeverityLevel.High,
                    RiskScore = rule07.BaseRiskScore,
                    SourceIp = securityEvent.SourceIp,
                    TargetedUsername = securityEvent.Username,
                    DetectedAtUtc = DateTime.UtcNow,
                    EvidenceEventIdsJson = JsonSerializer.Serialize(new List<Guid> { securityEvent.Id }),
                    RecommendedActions = "1. Require secondary MFA prompt.\n2. Review corporate policy regarding VPN/anonymizer egress.",
                    IsSimulated = securityEvent.IsSimulated
                });
            }
        }

        // Save detections and handle automatic incident creation
        foreach (var det in detections)
        {
            // Automatically create or link to active Incident if risk score >= 60 or severity is High/Critical
            if (det.RiskScore >= 60 || det.Severity >= SeverityLevel.High)
            {
                var incident = await CreateOrLinkIncidentAsync(det, securityEvent, ct);
                det.IncidentCreated = true;
                det.IncidentId = incident.Id;
            }

            await _context.ThreatDetections.AddAsync(det, ct);
            await _context.SaveChangesAsync(ct);

            // Real-time broadcast
            var threatDto = MapToThreatDto(det);
            await _securityHubService.BroadcastThreatDetectionAsync(threatDto);
        }

        return detections;
    }

    private async Task<Incident> CreateOrLinkIncidentAsync(ThreatDetection threat, SecurityEvent triggerEvent, CancellationToken ct)
    {
        // Check for existing open incident for this Source IP created within last 45 minutes
        var recentCutoff = DateTime.UtcNow.AddMinutes(-45);
        var existingIncident = await _context.Incidents
            .Include(i => i.IncidentEvents)
            .FirstOrDefaultAsync(i => i.SourceIp == threat.SourceIp &&
                                      (i.Status == IncidentStatus.Open || i.Status == IncidentStatus.Investigating) &&
                                      i.CreatedAtUtc >= recentCutoff, ct);

        if (existingIncident != null)
        {
            // Link event if not already linked
            if (!existingIncident.IncidentEvents.Any(ie => ie.SecurityEventId == triggerEvent.Id))
            {
                existingIncident.IncidentEvents.Add(new IncidentEvent
                {
                    IncidentId = existingIncident.Id,
                    SecurityEventId = triggerEvent.Id,
                    LinkedAtUtc = DateTime.UtcNow
                });
            }

            // Update risk score if higher
            if (threat.RiskScore > existingIncident.RiskScore)
            {
                existingIncident.RiskScore = threat.RiskScore;
                existingIncident.Severity = threat.Severity;
            }
            existingIncident.UpdatedAtUtc = DateTime.UtcNow;

            await _context.SaveChangesAsync(ct);
            return existingIncident;
        }

        // Generate new incident code
        var countToday = await _context.Incidents.CountAsync(ct) + 1;
        var code = $"SEC-{DateTime.UtcNow:yyyy}-{countToday:D4}";

        var newIncident = new Incident
        {
            IncidentCode = code,
            Title = $"{threat.ThreatType}: Suspicious Activity from {threat.SourceIp}",
            Description = threat.DetectionReason,
            Severity = threat.Severity,
            RiskScore = threat.RiskScore,
            Status = IncidentStatus.Open,
            SourceIp = threat.SourceIp,
            CreatedAtUtc = DateTime.UtcNow,
            IsSimulated = threat.IsSimulated
        };

        newIncident.IncidentEvents.Add(new IncidentEvent
        {
            IncidentId = newIncident.Id,
            SecurityEventId = triggerEvent.Id,
            LinkedAtUtc = DateTime.UtcNow
        });

        await _context.Incidents.AddAsync(newIncident, ct);

        // Create alert
        await _context.Alerts.AddAsync(new Alert
        {
            IncidentId = newIncident.Id,
            ThreatDetectionId = threat.Id,
            Title = $"Threat Detected: {code}",
            Message = threat.DetectionReason,
            Severity = threat.Severity,
            CreatedAtUtc = DateTime.UtcNow
        }, ct);

        await _context.SaveChangesAsync(ct);

        // Broadcast new incident
        var incidentDto = new IncidentDto
        {
            Id = newIncident.Id,
            IncidentCode = newIncident.IncidentCode,
            Title = newIncident.Title,
            Description = newIncident.Description,
            Severity = newIncident.Severity,
            RiskScore = newIncident.RiskScore,
            Status = newIncident.Status,
            SourceIp = newIncident.SourceIp,
            CreatedAtUtc = newIncident.CreatedAtUtc,
            IsSimulated = newIncident.IsSimulated,
            LinkedEventsCount = 1
        };

        await _securityHubService.BroadcastIncidentCreatedAsync(incidentDto);
        return newIncident;
    }

    public async Task<ApiResponse<PagedResult<ThreatDetectionDto>>> GetThreatsAsync(ThreatQueryParameters parameters, CancellationToken ct = default)
    {
        var query = _context.ThreatDetections.AsNoTracking().AsQueryable();

        if (parameters.Severity.HasValue)
        {
            query = query.Where(t => t.Severity == parameters.Severity.Value);
        }

        if (parameters.ThreatType.HasValue)
        {
            query = query.Where(t => t.ThreatType == parameters.ThreatType.Value);
        }

        if (!string.IsNullOrWhiteSpace(parameters.SourceIp))
        {
            query = query.Where(t => t.SourceIp.Contains(parameters.SourceIp));
        }

        if (parameters.MinRiskScore.HasValue)
        {
            query = query.Where(t => t.RiskScore >= parameters.MinRiskScore.Value);
        }

        if (parameters.FromUtc.HasValue)
        {
            query = query.Where(t => t.DetectedAtUtc >= parameters.FromUtc.Value);
        }

        if (parameters.ToUtc.HasValue)
        {
            query = query.Where(t => t.DetectedAtUtc <= parameters.ToUtc.Value);
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(t => t.DetectedAtUtc)
            .Skip((parameters.PageIndex - 1) * parameters.PageSize)
            .Take(parameters.PageSize)
            .ToListAsync(ct);

        var dtos = items.Select(MapToThreatDto).ToList();
        return ApiResponse<PagedResult<ThreatDetectionDto>>.Ok(new PagedResult<ThreatDetectionDto>(dtos, total, parameters.PageIndex, parameters.PageSize));
    }

    public async Task<ApiResponse<ThreatDetectionDto>> GetThreatByIdAsync(Guid id, CancellationToken ct = default)
    {
        var threat = await _context.ThreatDetections.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct);
        if (threat == null) return ApiResponse<ThreatDetectionDto>.Fail("Threat detection not found.");
        return ApiResponse<ThreatDetectionDto>.Ok(MapToThreatDto(threat));
    }

    public async Task<ApiResponse<ThreatStatisticsDto>> GetThreatStatisticsAsync(CancellationToken ct = default)
    {
        var allThreats = await _context.ThreatDetections.AsNoTracking().ToListAsync(ct);
        var total = allThreats.Count;
        var critical = allThreats.Count(t => t.Severity == SeverityLevel.Critical);
        var high = allThreats.Count(t => t.Severity == SeverityLevel.High);
        var avgRisk = total > 0 ? allThreats.Average(t => t.RiskScore) : 0;

        var byType = allThreats
            .GroupBy(t => t.ThreatType.ToString())
            .ToDictionary(g => g.Key, g => g.Count());

        var topIps = allThreats
            .GroupBy(t => t.SourceIp)
            .OrderByDescending(g => g.Count())
            .Take(5)
            .Select(g => new TopThreatIpDto
            {
                IpAddress = g.Key,
                ThreatCount = g.Count(),
                MaxRiskScore = g.Max(t => t.RiskScore)
            })
            .ToList();

        var stats = new ThreatStatisticsDto
        {
            TotalThreatsDetected = total,
            CriticalThreats = critical,
            HighThreats = high,
            AverageRiskScore = Math.Round(avgRisk, 1),
            ThreatsByType = byType,
            TopThreatIps = topIps
        };

        return ApiResponse<ThreatStatisticsDto>.Ok(stats);
    }

    private static ThreatDetectionDto MapToThreatDto(ThreatDetection t)
    {
        List<Guid> evidenceIds = new();
        if (!string.IsNullOrEmpty(t.EvidenceEventIdsJson))
        {
            try
            {
                evidenceIds = JsonSerializer.Deserialize<List<Guid>>(t.EvidenceEventIdsJson) ?? new();
            }
            catch { }
        }

        return new ThreatDetectionDto
        {
            Id = t.Id,
            RuleId = t.RuleId,
            RuleName = t.RuleName,
            ThreatType = t.ThreatType,
            DetectionReason = t.DetectionReason,
            Severity = t.Severity,
            RiskScore = t.RiskScore,
            SourceIp = t.SourceIp,
            TargetedUsername = t.TargetedUsername,
            DetectedAtUtc = t.DetectedAtUtc,
            EvidenceEventIds = evidenceIds,
            RecommendedActions = t.RecommendedActions,
            IncidentCreated = t.IncidentCreated,
            IncidentId = t.IncidentId,
            IsSimulated = t.IsSimulated
        };
    }
}
