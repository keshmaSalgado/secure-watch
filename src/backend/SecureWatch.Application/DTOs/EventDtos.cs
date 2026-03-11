using SecureWatch.Domain.Enums;

namespace SecureWatch.Application.DTOs;

public class CreateSecurityEventDto
{
    public string EventType { get; set; } = string.Empty;
    public EventCategory Category { get; set; }
    public SeverityLevel Severity { get; set; } = SeverityLevel.Low;
    public string SourceIp { get; set; } = string.Empty;
    public string? DestinationIp { get; set; }
    public string? UserIdRef { get; set; }
    public string? Username { get; set; }
    public DateTime? EventTimestampUtc { get; set; }
    public string? DeviceInfo { get; set; }
    public string? UserAgent { get; set; }
    public string Description { get; set; } = string.Empty;
    public string? MetadataJson { get; set; }
    public bool IsSimulated { get; set; } = false;
}

public class SecurityEventDto
{
    public Guid Id { get; set; }
    public string EventType { get; set; } = string.Empty;
    public EventCategory Category { get; set; }
    public string CategoryName => Category.ToString();
    public SeverityLevel Severity { get; set; }
    public string SeverityName => Severity.ToString();
    public string SourceIp { get; set; } = string.Empty;
    public string? DestinationIp { get; set; }
    public string? UserIdRef { get; set; }
    public string? Username { get; set; }
    public DateTime EventTimestampUtc { get; set; }
    public string? DeviceInfo { get; set; }
    public string? UserAgent { get; set; }
    public string Description { get; set; } = string.Empty;
    public string ProcessingStatus { get; set; } = "Processed";
    public string? MetadataJson { get; set; }
    public bool IsSimulated { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}

public class EventQueryParameters
{
    public int PageIndex { get; set; } = 1;
    public int PageSize { get; set; } = 20;
    public EventCategory? Category { get; set; }
    public SeverityLevel? Severity { get; set; }
    public string? SourceIp { get; set; }
    public string? Username { get; set; }
    public string? SearchTerm { get; set; }
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
}

public class EventStatisticsDto
{
    public int TotalEvents { get; set; }
    public int HighSeverityEvents { get; set; }
    public int FailedLoginsToday { get; set; }
    public int UniqueIpsSeenToday { get; set; }
    public Dictionary<string, int> EventsByCategory { get; set; } = new();
    public Dictionary<string, int> EventsBySeverity { get; set; } = new();
}

