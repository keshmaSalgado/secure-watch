using SecureWatch.Domain.Common;
using SecureWatch.Domain.Enums;

namespace SecureWatch.Domain.Entities;

public class Alert : BaseEntity, IAggregateRoot
{
    public Guid? IncidentId { get; set; }
    public Guid? ThreatDetectionId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public bool IsAcknowledged { get; set; } = false;
    public string? AcknowledgedById { get; set; }
    public string? AcknowledgedByName { get; set; }
    public DateTime? AcknowledgedAtUtc { get; set; }

    // Navigation properties
    public virtual Incident? Incident { get; set; }
    public virtual ThreatDetection? ThreatDetection { get; set; }
}

