using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Entities;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class IncidentService : IIncidentService
{
    private readonly SecureWatchDbContext _context;
    private readonly ISecurityHubService _securityHubService;
    private readonly IAuditLogService _auditLogService;
    private readonly ILogger<IncidentService> _logger;

    public IncidentService(
        SecureWatchDbContext context,
        ISecurityHubService securityHubService,
        IAuditLogService auditLogService,
        ILogger<IncidentService> logger)
    {
        _context = context;
        _securityHubService = securityHubService;
        _auditLogService = auditLogService;
        _logger = logger;
    }

    public async Task<ApiResponse<PagedResult<IncidentDto>>> GetIncidentsAsync(IncidentQueryParameters parameters, CancellationToken ct = default)
    {
        var query = _context.Incidents
            .AsNoTracking()
            .Include(i => i.IncidentEvents)
            .AsQueryable();

        if (parameters.Status.HasValue)
        {
            query = query.Where(i => i.Status == parameters.Status.Value);
        }

        if (parameters.Severity.HasValue)
        {
            query = query.Where(i => i.Severity == parameters.Severity.Value);
        }

        if (!string.IsNullOrWhiteSpace(parameters.AssignedAnalystId))
        {
            query = query.Where(i => i.AssignedAnalystId == parameters.AssignedAnalystId);
        }

        if (!string.IsNullOrWhiteSpace(parameters.SourceIp))
        {
            query = query.Where(i => i.SourceIp != null && i.SourceIp.Contains(parameters.SourceIp));
        }

        if (!string.IsNullOrWhiteSpace(parameters.SearchTerm))
        {
            var term = parameters.SearchTerm.ToLower();
            query = query.Where(i => i.Title.ToLower().Contains(term) ||
                                     i.IncidentCode.ToLower().Contains(term) ||
                                     i.Description.ToLower().Contains(term));
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(i => i.CreatedAtUtc)
            .Skip((parameters.PageIndex - 1) * parameters.PageSize)
            .Take(parameters.PageSize)
            .ToListAsync(ct);

        var dtos = items.Select(MapToSummaryDto).ToList();
        return ApiResponse<PagedResult<IncidentDto>>.Ok(new PagedResult<IncidentDto>(dtos, total, parameters.PageIndex, parameters.PageSize));
    }

    public async Task<ApiResponse<IncidentDto>> GetIncidentByIdAsync(Guid id, CancellationToken ct = default)
    {
        var incident = await _context.Incidents
            .AsNoTracking()
            .Include(i => i.Notes)
            .Include(i => i.IncidentEvents)
                .ThenInclude(ie => ie.SecurityEvent)
            .FirstOrDefaultAsync(i => i.Id == id, ct);

        if (incident == null) return ApiResponse<IncidentDto>.Fail("Incident not found.");

        var dto = new IncidentDto
        {
            Id = incident.Id,
            IncidentCode = incident.IncidentCode,
            Title = incident.Title,
            Description = incident.Description,
            Severity = incident.Severity,
            RiskScore = incident.RiskScore,
            Status = incident.Status,
            AssignedAnalystId = incident.AssignedAnalystId,
            AssignedAnalystName = incident.AssignedAnalystName,
            SourceIp = incident.SourceIp,
            CreatedAtUtc = incident.CreatedAtUtc,
            UpdatedAtUtc = incident.UpdatedAtUtc,
            ResolvedAtUtc = incident.ResolvedAtUtc,
            ResolutionSummary = incident.ResolutionSummary,
            RootCause = incident.RootCause,
            IsSimulated = incident.IsSimulated,
            LinkedEventsCount = incident.IncidentEvents.Count,
            Notes = incident.Notes.OrderBy(n => n.CreatedAtUtc).Select(n => new IncidentNoteDto
            {
                Id = n.Id,
                IncidentId = n.IncidentId,
                AuthorId = n.AuthorId,
                AuthorName = n.AuthorName,
                NoteText = n.NoteText,
                IsInternalOnly = n.IsInternalOnly,
                CreatedAtUtc = n.CreatedAtUtc
            }).ToList(),
            LinkedEvents = incident.IncidentEvents.Select(ie => new SecurityEventDto
            {
                Id = ie.SecurityEvent.Id,
                EventType = ie.SecurityEvent.EventType,
                Category = ie.SecurityEvent.Category,
                Severity = ie.SecurityEvent.Severity,
                SourceIp = ie.SecurityEvent.SourceIp,
                DestinationIp = ie.SecurityEvent.DestinationIp,
                Username = ie.SecurityEvent.Username,
                EventTimestampUtc = ie.SecurityEvent.EventTimestampUtc,
                DeviceInfo = ie.SecurityEvent.DeviceInfo,
                UserAgent = ie.SecurityEvent.UserAgent,
                Description = ie.SecurityEvent.Description,
                ProcessingStatus = ie.SecurityEvent.ProcessingStatus,
                IsSimulated = ie.SecurityEvent.IsSimulated
            }).ToList()
        };

        return ApiResponse<IncidentDto>.Ok(dto);
    }

    public async Task<ApiResponse<IncidentDto>> CreateIncidentAsync(CreateIncidentDto request, CancellationToken ct = default)
    {
        var countToday = await _context.Incidents.CountAsync(ct) + 1;
        var code = $"SEC-{DateTime.UtcNow:yyyy}-{countToday:D4}";

        var incident = new Incident
        {
            IncidentCode = code,
            Title = request.Title,
            Description = request.Description,
            Severity = request.Severity,
            RiskScore = request.RiskScore,
            Status = IncidentStatus.Open,
            SourceIp = request.SourceIp,
            AssignedAnalystId = request.AssignedAnalystId,
            CreatedAtUtc = DateTime.UtcNow,
            IsSimulated = request.IsSimulated
        };

        if (request.LinkedEventIds != null && request.LinkedEventIds.Any())
        {
            foreach (var evId in request.LinkedEventIds)
            {
                incident.IncidentEvents.Add(new IncidentEvent
                {
                    IncidentId = incident.Id,
                    SecurityEventId = evId,
                    LinkedAtUtc = DateTime.UtcNow
                });
            }
        }

        await _context.Incidents.AddAsync(incident, ct);
        await _context.SaveChangesAsync(ct);

        var dto = MapToSummaryDto(incident);
        await _securityHubService.BroadcastIncidentCreatedAsync(dto);
        await _auditLogService.LogAsync(null, "System", "IncidentCreated", "Incident", incident.Id.ToString(), "Local", null, new { code, request.Title }, ct);

        return ApiResponse<IncidentDto>.Ok(dto, "Incident created successfully.");
    }

    public async Task<ApiResponse<IncidentDto>> UpdateIncidentAsync(Guid id, UpdateIncidentDto request, CancellationToken ct = default)
    {
        var incident = await _context.Incidents.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (incident == null) return ApiResponse<IncidentDto>.Fail("Incident not found.");

        if (!string.IsNullOrWhiteSpace(request.Title)) incident.Title = request.Title;
        if (!string.IsNullOrWhiteSpace(request.Description)) incident.Description = request.Description;
        if (request.Severity.HasValue) incident.Severity = request.Severity.Value;
        if (request.Status.HasValue) incident.Status = request.Status.Value;
        if (!string.IsNullOrWhiteSpace(request.AssignedAnalystId)) incident.AssignedAnalystId = request.AssignedAnalystId;

        incident.UpdatedAtUtc = DateTime.UtcNow;
        await _context.SaveChangesAsync(ct);

        var dto = MapToSummaryDto(incident);
        await _securityHubService.BroadcastIncidentUpdatedAsync(dto);
        await _auditLogService.LogAsync(null, "System", "IncidentUpdated", "Incident", incident.Id.ToString(), "Local", null, request, ct);

        return ApiResponse<IncidentDto>.Ok(dto, "Incident updated successfully.");
    }

    public async Task<ApiResponse<IncidentDto>> AssignAnalystAsync(Guid id, string analystId, CancellationToken ct = default)
    {
        var incident = await _context.Incidents.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (incident == null) return ApiResponse<IncidentDto>.Fail("Incident not found.");

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == analystId || u.Email == analystId, ct);
        incident.AssignedAnalystId = user?.Id ?? analystId;
        incident.AssignedAnalystName = user != null ? $"{user.FirstName} {user.LastName}".Trim() : analystId;
        incident.Status = IncidentStatus.Investigating;
        incident.UpdatedAtUtc = DateTime.UtcNow;

        await _context.SaveChangesAsync(ct);

        var dto = MapToSummaryDto(incident);
        await _securityHubService.BroadcastIncidentUpdatedAsync(dto);
        await _auditLogService.LogAsync(analystId, "System", "IncidentAssigned", "Incident", incident.Id.ToString(), "Local", null, new { Analyst = incident.AssignedAnalystName }, ct);

        return ApiResponse<IncidentDto>.Ok(dto, $"Incident assigned to {incident.AssignedAnalystName}.");
    }

    public async Task<ApiResponse<IncidentNoteDto>> AddNoteAsync(Guid id, AddIncidentNoteDto request, string authorId, string authorName, CancellationToken ct = default)
    {
        var incident = await _context.Incidents.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (incident == null) return ApiResponse<IncidentNoteDto>.Fail("Incident not found.");

        var note = new IncidentNote
        {
            IncidentId = id,
            AuthorId = authorId,
            AuthorName = authorName,
            NoteText = request.NoteText,
            IsInternalOnly = request.IsInternalOnly,
            CreatedAtUtc = DateTime.UtcNow
        };

        await _context.IncidentNotes.AddAsync(note, ct);
        incident.UpdatedAtUtc = DateTime.UtcNow;
        await _context.SaveChangesAsync(ct);

        var noteDto = new IncidentNoteDto
        {
            Id = note.Id,
            IncidentId = note.IncidentId,
            AuthorId = note.AuthorId,
            AuthorName = note.AuthorName,
            NoteText = note.NoteText,
            IsInternalOnly = note.IsInternalOnly,
            CreatedAtUtc = note.CreatedAtUtc
        };

        await _auditLogService.LogAsync(authorId, authorName, "IncidentNoteAdded", "IncidentNote", note.Id.ToString(), "Local", null, new { IncidentCode = incident.IncidentCode }, ct);

        return ApiResponse<IncidentNoteDto>.Ok(noteDto, "Investigation note added.");
    }

    public async Task<ApiResponse<IncidentDto>> ResolveIncidentAsync(Guid id, ResolveIncidentDto request, CancellationToken ct = default)
    {
        var incident = await _context.Incidents.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (incident == null) return ApiResponse<IncidentDto>.Fail("Incident not found.");

        incident.Status = IncidentStatus.Resolved;
        incident.ResolvedAtUtc = DateTime.UtcNow;
        incident.ResolutionSummary = request.ResolutionSummary;
        incident.RootCause = request.RootCause;
        incident.UpdatedAtUtc = DateTime.UtcNow;

        await _context.SaveChangesAsync(ct);

        var dto = MapToSummaryDto(incident);
        await _securityHubService.BroadcastIncidentUpdatedAsync(dto);
        await _auditLogService.LogAsync(null, "System", "IncidentResolved", "Incident", incident.Id.ToString(), "Local", null, request, ct);

        return ApiResponse<IncidentDto>.Ok(dto, "Incident resolved successfully.");
    }

    private static IncidentDto MapToSummaryDto(Incident i)
    {
        return new IncidentDto
        {
            Id = i.Id,
            IncidentCode = i.IncidentCode,
            Title = i.Title,
            Description = i.Description,
            Severity = i.Severity,
            RiskScore = i.RiskScore,
            Status = i.Status,
            AssignedAnalystId = i.AssignedAnalystId,
            AssignedAnalystName = i.AssignedAnalystName,
            SourceIp = i.SourceIp,
            CreatedAtUtc = i.CreatedAtUtc,
            UpdatedAtUtc = i.UpdatedAtUtc,
            ResolvedAtUtc = i.ResolvedAtUtc,
            ResolutionSummary = i.ResolutionSummary,
            RootCause = i.RootCause,
            IsSimulated = i.IsSimulated,
            LinkedEventsCount = i.IncidentEvents?.Count ?? 0
        };
    }
}

