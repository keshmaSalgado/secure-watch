using Microsoft.EntityFrameworkCore;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class DashboardService : IDashboardService
{
    private readonly SecureWatchDbContext _context;

    public DashboardService(SecureWatchDbContext context)
    {
        _context = context;
    }

    public async Task<ApiResponse<DashboardOverviewDto>> GetOverviewAsync(CancellationToken ct = default)
    {
        var totalEvents = await _context.SecurityEvents.CountAsync(ct);
        var totalThreats = await _context.ThreatDetections.CountAsync(ct);
        var criticalIncidents = await _context.Incidents.CountAsync(i => i.Severity == SeverityLevel.Critical, ct);
        var activeIncidents = await _context.Incidents.CountAsync(i => i.Status == IncidentStatus.Open || i.Status == IncidentStatus.Investigating, ct);
        var failedLogins = await _context.SecurityEvents.CountAsync(e => e.Category == EventCategory.FailedLogin, ct);
        var suspiciousIps = await _context.IPReputations.CountAsync(ip => ip.IsMalicious || ip.ReputationScore >= 60, ct);

        // Overall risk score: weighted average of recent incident risk scores and threat detections
        var recentThreats = await _context.ThreatDetections
            .OrderByDescending(t => t.DetectedAtUtc)
            .Take(20)
            .Select(t => t.RiskScore)
            .ToListAsync(ct);

        var overallRisk = recentThreats.Any() ? recentThreats.Average() : 15.0;

        var recentEvents = await _context.SecurityEvents
            .AsNoTracking()
            .OrderByDescending(e => e.EventTimestampUtc)
            .Take(8)
            .Select(e => new SecurityEventDto
            {
                Id = e.Id,
                EventType = e.EventType,
                Category = e.Category,
                Severity = e.Severity,
                SourceIp = e.SourceIp,
                DestinationIp = e.DestinationIp,
                Username = e.Username,
                EventTimestampUtc = e.EventTimestampUtc,
                Description = e.Description,
                ProcessingStatus = e.ProcessingStatus,
                IsSimulated = e.IsSimulated
            })
            .ToListAsync(ct);

        var recentIncidents = await _context.Incidents
            .AsNoTracking()
            .OrderByDescending(i => i.CreatedAtUtc)
            .Take(5)
            .Select(i => new IncidentDto
            {
                Id = i.Id,
                IncidentCode = i.IncidentCode,
                Title = i.Title,
                Description = i.Description,
                Severity = i.Severity,
                RiskScore = i.RiskScore,
                Status = i.Status,
                AssignedAnalystName = i.AssignedAnalystName,
                SourceIp = i.SourceIp,
                CreatedAtUtc = i.CreatedAtUtc,
                IsSimulated = i.IsSimulated
            })
            .ToListAsync(ct);

        var overview = new DashboardOverviewDto
        {
            TotalEvents = totalEvents,
            TotalThreatsDetected = totalThreats,
            CriticalIncidents = criticalIncidents,
            ActiveIncidents = activeIncidents,
            FailedLoginAttempts = failedLogins,
            SuspiciousIpCount = suspiciousIps,
            OverallRiskScore = Math.Round(overallRisk, 1),
            RecentEvents = recentEvents,
            RecentIncidents = recentIncidents
        };

        return ApiResponse<DashboardOverviewDto>.Ok(overview);
    }

    public async Task<ApiResponse<List<ThreatTrendDto>>> GetThreatTrendsAsync(int hours = 24, CancellationToken ct = default)
    {
        var cutoff = DateTime.UtcNow.AddHours(-hours);
        var events = await _context.SecurityEvents
            .AsNoTracking()
            .Where(e => e.EventTimestampUtc >= cutoff)
            .Select(e => new { e.EventTimestampUtc, e.Category })
            .ToListAsync(ct);

        var threats = await _context.ThreatDetections
            .AsNoTracking()
            .Where(t => t.DetectedAtUtc >= cutoff)
            .Select(t => t.DetectedAtUtc)
            .ToListAsync(ct);

        var result = new List<ThreatTrendDto>();
        for (int i = hours - 1; i >= 0; i--)
        {
            var bucketStart = DateTime.UtcNow.AddHours(-i);
            var bucketHour = bucketStart.Hour;
            var label = $"{bucketHour:D2}:00";

            var evCount = events.Count(e => e.EventTimestampUtc.Hour == bucketHour && e.EventTimestampUtc.Date == bucketStart.Date);
            var thCount = threats.Count(t => t.Hour == bucketHour && t.Date == bucketStart.Date);
            var failedCount = events.Count(e => e.Category == EventCategory.FailedLogin && e.EventTimestampUtc.Hour == bucketHour && e.EventTimestampUtc.Date == bucketStart.Date);

            result.Add(new ThreatTrendDto
            {
                TimeLabel = label,
                EventCount = evCount,
                ThreatCount = thCount,
                FailedLogins = failedCount
            });
        }

        return ApiResponse<List<ThreatTrendDto>>.Ok(result);
    }

    public async Task<ApiResponse<RiskDistributionDto>> GetRiskDistributionAsync(CancellationToken ct = default)
    {
        var threats = await _context.ThreatDetections.AsNoTracking().ToListAsync(ct);

        var dist = new RiskDistributionDto
        {
            LowCount = threats.Count(t => t.RiskScore < 30),
            MediumCount = threats.Count(t => t.RiskScore >= 30 && t.RiskScore < 60),
            HighCount = threats.Count(t => t.RiskScore >= 60 && t.RiskScore < 80),
            CriticalCount = threats.Count(t => t.RiskScore >= 80)
        };

        return ApiResponse<RiskDistributionDto>.Ok(dist);
    }
}

