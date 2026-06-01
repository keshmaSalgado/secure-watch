using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Entities;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class SecurityEventService : ISecurityEventService
{
    private readonly SecureWatchDbContext _context;
    private readonly IThreatDetectionEngine _threatEngine;
    private readonly IIpReputationService _ipReputationService;
    private readonly ISecurityHubService _securityHubService;
    private readonly ILogger<SecurityEventService> _logger;

    public SecurityEventService(
        SecureWatchDbContext context,
        IThreatDetectionEngine threatEngine,
        IIpReputationService ipReputationService,
        ISecurityHubService securityHubService,
        ILogger<SecurityEventService> logger)
    {
        _context = context;
        _threatEngine = threatEngine;
        _ipReputationService = ipReputationService;
        _securityHubService = securityHubService;
        _logger = logger;
    }

    public async Task<ApiResponse<SecurityEventDto>> IngestEventAsync(CreateSecurityEventDto request, CancellationToken ct = default)
    {
        var securityEvent = new SecurityEvent
        {
            EventType = request.EventType,
            Category = request.Category,
            Severity = request.Severity,
            SourceIp = request.SourceIp,
            DestinationIp = request.DestinationIp,
            UserIdRef = request.UserIdRef,
            Username = request.Username,
            EventTimestampUtc = request.EventTimestampUtc ?? DateTime.UtcNow,
            DeviceInfo = request.DeviceInfo,
            UserAgent = request.UserAgent,
            Description = request.Description,
            MetadataJson = request.MetadataJson,
            ProcessingStatus = "Processed",
            IsSimulated = request.IsSimulated
        };

        await _context.SecurityEvents.AddAsync(securityEvent, ct);
        await _context.SaveChangesAsync(ct);

        // Track IP activity
        var isSuspicious = request.Category == EventCategory.FailedLogin || request.Severity >= SeverityLevel.High;
        await _ipReputationService.RecordIpActivityAsync(securityEvent.SourceIp, isSuspicious, ct);

        // Real-time broadcast
        var dto = MapToDto(securityEvent);
        await _securityHubService.BroadcastSecurityEventAsync(dto);

        // Evaluate threat detection rules
        try
        {
            await _threatEngine.EvaluateEventAsync(securityEvent, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error evaluating threat detection rules for event {EventId}", securityEvent.Id);
        }

        return ApiResponse<SecurityEventDto>.Ok(dto, "Event ingested and processed.");
    }

    public async Task<ApiResponse<List<SecurityEventDto>>> IngestBatchAsync(List<CreateSecurityEventDto> requests, CancellationToken ct = default)
    {
        var dtos = new List<SecurityEventDto>();
        foreach (var req in requests)
        {
            var res = await IngestEventAsync(req, ct);
            if (res.Success && res.Data != null)
            {
                dtos.Add(res.Data);
            }
        }
        return ApiResponse<List<SecurityEventDto>>.Ok(dtos, $"Successfully ingested {dtos.Count} events.");
    }

    public async Task<ApiResponse<PagedResult<SecurityEventDto>>> GetEventsAsync(EventQueryParameters parameters, CancellationToken ct = default)
    {
        var query = _context.SecurityEvents.AsNoTracking().AsQueryable();

        if (parameters.Category.HasValue)
        {
            query = query.Where(e => e.Category == parameters.Category.Value);
        }

        if (parameters.Severity.HasValue)
        {
            query = query.Where(e => e.Severity == parameters.Severity.Value);
        }

        if (!string.IsNullOrWhiteSpace(parameters.SourceIp))
        {
            query = query.Where(e => e.SourceIp.Contains(parameters.SourceIp));
        }

        if (!string.IsNullOrWhiteSpace(parameters.Username))
        {
            query = query.Where(e => e.Username != null && e.Username.ToLower().Contains(parameters.Username.ToLower()));
        }

        if (!string.IsNullOrWhiteSpace(parameters.SearchTerm))
        {
            var term = parameters.SearchTerm.ToLower();
            query = query.Where(e => e.Description.ToLower().Contains(term) ||
                                     e.EventType.ToLower().Contains(term) ||
                                     e.SourceIp.Contains(term));
        }

        if (parameters.FromUtc.HasValue)
        {
            query = query.Where(e => e.EventTimestampUtc >= parameters.FromUtc.Value);
        }

        if (parameters.ToUtc.HasValue)
        {
            query = query.Where(e => e.EventTimestampUtc <= parameters.ToUtc.Value);
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(e => e.EventTimestampUtc)
            .Skip((parameters.PageIndex - 1) * parameters.PageSize)
            .Take(parameters.PageSize)
            .ToListAsync(ct);

        var dtos = items.Select(MapToDto).ToList();
        return ApiResponse<PagedResult<SecurityEventDto>>.Ok(new PagedResult<SecurityEventDto>(dtos, total, parameters.PageIndex, parameters.PageSize));
    }

    public async Task<ApiResponse<SecurityEventDto>> GetEventByIdAsync(Guid id, CancellationToken ct = default)
    {
        var securityEvent = await _context.SecurityEvents.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id, ct);
        if (securityEvent == null) return ApiResponse<SecurityEventDto>.Fail("Security event not found.");
        return ApiResponse<SecurityEventDto>.Ok(MapToDto(securityEvent));
    }

    public async Task<ApiResponse<EventStatisticsDto>> GetStatisticsAsync(CancellationToken ct = default)
    {
        var today = DateTime.UtcNow.Date;
        var events = await _context.SecurityEvents.AsNoTracking().ToListAsync(ct);

        var total = events.Count;
        var high = events.Count(e => e.Severity >= SeverityLevel.High);
        var failedToday = events.Count(e => e.Category == EventCategory.FailedLogin && e.EventTimestampUtc >= today);
        var uniqueIpsToday = events.Where(e => e.EventTimestampUtc >= today).Select(e => e.SourceIp).Distinct().Count();

        var byCat = events.GroupBy(e => e.Category.ToString()).ToDictionary(g => g.Key, g => g.Count());
        var bySev = events.GroupBy(e => e.Severity.ToString()).ToDictionary(g => g.Key, g => g.Count());

        var stats = new EventStatisticsDto
        {
            TotalEvents = total,
            HighSeverityEvents = high,
            FailedLoginsToday = failedToday,
            UniqueIpsSeenToday = uniqueIpsToday,
            EventsByCategory = byCat,
            EventsBySeverity = bySev
        };

        return ApiResponse<EventStatisticsDto>.Ok(stats);
    }

    private static SecurityEventDto MapToDto(SecurityEvent e)
    {
        return new SecurityEventDto
        {
            Id = e.Id,
            EventType = e.EventType,
            Category = e.Category,
            Severity = e.Severity,
            SourceIp = e.SourceIp,
            DestinationIp = e.DestinationIp,
            UserIdRef = e.UserIdRef,
            Username = e.Username,
            EventTimestampUtc = e.EventTimestampUtc,
            DeviceInfo = e.DeviceInfo,
            UserAgent = e.UserAgent,
            Description = e.Description,
            ProcessingStatus = e.ProcessingStatus,
            MetadataJson = e.MetadataJson,
            IsSimulated = e.IsSimulated,
            CreatedAtUtc = e.CreatedAtUtc
        };
    }
}

