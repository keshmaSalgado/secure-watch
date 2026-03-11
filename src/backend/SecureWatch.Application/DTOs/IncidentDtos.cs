using SecureWatch.Domain.Enums;

namespace SecureWatch.Application.DTOs;

public class IncidentDto
{
    public Guid Id { get; set; }
    public string IncidentCode { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public string SeverityName => Severity.ToString();
    public int RiskScore { get; set; }
    public IncidentStatus Status { get; set; }
    public string StatusName => Status.ToString();
    public string? AssignedAnalystId { get; set; }
    public string? AssignedAnalystName { get; set; }
    public string? SourceIp { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? UpdatedAtUtc { get; set; }
    public DateTime? ResolvedAtUtc { get; set; }
    public string? ResolutionSummary { get; set; }
    public string? RootCause { get; set; }
    public bool IsSimulated { get; set; }
    public int LinkedEventsCount { get; set; }
    public List<IncidentNoteDto> Notes { get; set; } = new();
    public List<SecurityEventDto> LinkedEvents { get; set; } = new();
}

public class IncidentNoteDto
{
    public Guid Id { get; set; }
    public Guid IncidentId { get; set; }
    public string AuthorId { get; set; } = string.Empty;
    public string AuthorName { get; set; } = string.Empty;
    public string NoteText { get; set; } = string.Empty;
    public bool IsInternalOnly { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}

public class CreateIncidentDto
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; } = SeverityLevel.Medium;
    public int RiskScore { get; set; } = 50;
    public string? SourceIp { get; set; }
    public string? AssignedAnalystId { get; set; }
    public List<Guid>? LinkedEventIds { get; set; }
    public bool IsSimulated { get; set; } = false;
}

public class UpdateIncidentDto
{
    public string? Title { get; set; }
    public string? Description { get; set; }
    public SeverityLevel? Severity { get; set; }
    public IncidentStatus? Status { get; set; }
    public string? AssignedAnalystId { get; set; }
}

public class AddIncidentNoteDto
{
    public string NoteText { get; set; } = string.Empty;
    public bool IsInternalOnly { get; set; } = false;
}

public class ResolveIncidentDto
{
    public string ResolutionSummary { get; set; } = string.Empty;
    public string? RootCause { get; set; }
}

public class IncidentQueryParameters
{
    public int PageIndex { get; set; } = 1;
    public int PageSize { get; set; } = 20;
    public IncidentStatus? Status { get; set; }
    public SeverityLevel? Severity { get; set; }
    public string? AssignedAnalystId { get; set; }
    public string? SourceIp { get; set; }
    public string? SearchTerm { get; set; }
}

