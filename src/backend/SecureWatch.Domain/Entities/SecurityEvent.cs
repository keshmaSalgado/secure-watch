using SecureWatch.Domain.Common;
using SecureWatch.Domain.Enums;

namespace SecureWatch.Domain.Entities;

public class SecurityEvent : BaseEntity, IAggregateRoot
{
    public string EventType { get; set; } = string.Empty;
    public EventCategory Category { get; set; }
    public SeverityLevel Severity { get; set; }
    public string SourceIp { get; set; } = string.Empty;
    public string? DestinationIp { get; set; }
    public string? UserIdRef { get; set; }
    public string? Username { get; set; }
    public DateTime EventTimestampUtc { get; set; } = DateTime.UtcNow;
    public string? DeviceInfo { get; set; }
    public string? UserAgent { get; set; }
    public string Description { get; set; } = string.Empty;
    public string ProcessingStatus { get; set; } = "Processed";
    public string? MetadataJson { get; set; }
    public bool IsSimulated { get; set; } = false;

    // Navigation properties
    public virtual ICollection<IncidentEvent> IncidentEvents { get; set; } = new List<IncidentEvent>();
}

