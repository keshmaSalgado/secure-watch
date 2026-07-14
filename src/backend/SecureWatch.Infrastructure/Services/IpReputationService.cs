using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Entities;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class IpReputationService : IIpReputationService
{
    private readonly SecureWatchDbContext _context;
    private readonly ICacheService _cache;
    private readonly ILogger<IpReputationService> _logger;

    public IpReputationService(
        SecureWatchDbContext context,
        ICacheService cache,
        ILogger<IpReputationService> logger)
    {
        _context = context;
        _cache = cache;
        _logger = logger;
    }

    public async Task<ApiResponse<IpReputationDto>> GetReputationAsync(string ipAddress, CancellationToken ct = default)
    {
        var cacheKey = $"ip_rep_{ipAddress}";
        var cached = await _cache.GetAsync<IpReputationDto>(cacheKey, ct);
        if (cached != null)
        {
            return ApiResponse<IpReputationDto>.Ok(cached);
        }

        var ipRecord = await _context.IPReputations.FirstOrDefaultAsync(i => i.IpAddress == ipAddress, ct);

        if (ipRecord == null)
        {
            ipRecord = GenerateSimulatedReputation(ipAddress);
            await _context.IPReputations.AddAsync(ipRecord, ct);
            await _context.SaveChangesAsync(ct);
        }

        // Fetch recent events and threats for this IP
        var recentEvents = await _context.SecurityEvents
            .AsNoTracking()
            .Where(e => e.SourceIp == ipAddress)
            .OrderByDescending(e => e.EventTimestampUtc)
            .Take(10)
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

        var recentThreats = await _context.ThreatDetections
            .AsNoTracking()
            .Where(t => t.SourceIp == ipAddress)
            .OrderByDescending(t => t.DetectedAtUtc)
            .Take(5)
            .Select(t => new ThreatDetectionDto
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
                RecommendedActions = t.RecommendedActions,
                IncidentCreated = t.IncidentCreated,
                IncidentId = t.IncidentId,
                IsSimulated = t.IsSimulated
            })
            .ToListAsync(ct);

        var dto = new IpReputationDto
        {
            IpAddress = ipRecord.IpAddress,
            ReputationScore = ipRecord.ReputationScore,
            IsMalicious = ipRecord.IsMalicious,
            IsTor = ipRecord.IsTor,
            IsVpnOrProxy = ipRecord.IsVpnOrProxy,
            CountryCode = ipRecord.CountryCode,
            CountryName = ipRecord.CountryName,
            Region = ipRecord.Region,
            City = ipRecord.City,
            Isp = ipRecord.Isp,
            Asn = ipRecord.Asn,
            TotalEventsRecorded = ipRecord.TotalEventsRecorded,
            LastCheckedAtUtc = ipRecord.LastCheckedAtUtc,
            RecentEvents = recentEvents,
            RecentThreats = recentThreats
        };

        await _cache.SetAsync(cacheKey, dto, TimeSpan.FromMinutes(15), ct);
        return ApiResponse<IpReputationDto>.Ok(dto);
    }

    public async Task<ApiResponse<IpReputationDto>> ForceRefreshAsync(string ipAddress, CancellationToken ct = default)
    {
        await _cache.RemoveAsync($"ip_rep_{ipAddress}", ct);
        var ipRecord = await _context.IPReputations.FirstOrDefaultAsync(i => i.IpAddress == ipAddress, ct);
        if (ipRecord != null)
        {
            ipRecord.LastCheckedAtUtc = DateTime.UtcNow;
            await _context.SaveChangesAsync(ct);
        }
        return await GetReputationAsync(ipAddress, ct);
    }

    public async Task RecordIpActivityAsync(string ipAddress, bool isSuspicious, CancellationToken ct = default)
    {
        var record = await _context.IPReputations.FirstOrDefaultAsync(i => i.IpAddress == ipAddress, ct);
        if (record == null)
        {
            record = GenerateSimulatedReputation(ipAddress);
            await _context.IPReputations.AddAsync(record, ct);
        }

        record.TotalEventsRecorded++;
        if (isSuspicious && record.ReputationScore < 95)
        {
            record.ReputationScore = Math.Min(100, record.ReputationScore + 10);
            if (record.ReputationScore >= 80)
            {
                record.IsMalicious = true;
            }
        }
        record.LastCheckedAtUtc = DateTime.UtcNow;

        await _context.SaveChangesAsync(ct);
        await _cache.RemoveAsync($"ip_rep_{ipAddress}", ct);
    }

    private static IPReputation GenerateSimulatedReputation(string ipAddress)
    {
        // Safe internal or private subnets
        if (ipAddress.StartsWith("10.") || ipAddress.StartsWith("192.168.") || ipAddress == "127.0.0.1" || ipAddress == "::1")
        {
            return new IPReputation
            {
                IpAddress = ipAddress,
                ReputationScore = 0,
                IsMalicious = false,
                IsTor = false,
                IsVpnOrProxy = false,
                CountryCode = "US",
                CountryName = "Private Network",
                Region = "Internal",
                City = "Local Subnet",
                Isp = "Enterprise Intranet",
                Asn = "AS-INTERNAL",
                TotalEventsRecorded = 1,
                LastCheckedAtUtc = DateTime.UtcNow
            };
        }

        // Deterministic hash-based geo/reputation generation for simulation
        var hash = (uint)Math.Abs(ipAddress.GetHashCode());
        var isHostile = hash % 5 == 0; // 20% simulated suspicious/hostile
        var score = isHostile ? 70 + (int)(hash % 30) : (int)(hash % 40);

        var countries = new[]
        {
            ("US", "United States", "Virginia", "Ashburn", "Amazon AWS", "AS16509"),
            ("DE", "Germany", "Hesse", "Frankfurt", "Hetzner Online", "AS24940"),
            ("NL", "Netherlands", "North Holland", "Amsterdam", "DigitalOcean", "AS14061"),
            ("GB", "United Kingdom", "London", "London", "British Telecom", "AS2856"),
            ("JP", "Japan", "Tokyo", "Tokyo", "NTT Communications", "AS4713"),
            ("SG", "Singapore", "Central", "Singapore", "Singtel", "AS7473")
        };

        var selected = countries[hash % countries.Length];

        return new IPReputation
        {
            IpAddress = ipAddress,
            ReputationScore = score,
            IsMalicious = isHostile,
            IsTor = isHostile && (hash % 2 == 0),
            IsVpnOrProxy = (hash % 3 == 0),
            CountryCode = selected.Item1,
            CountryName = selected.Item2,
            Region = selected.Item3,
            City = selected.Item4,
            Isp = selected.Item5,
            Asn = selected.Item6,
            TotalEventsRecorded = 1,
            LastCheckedAtUtc = DateTime.UtcNow
        };
    }
}

