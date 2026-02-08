using SecureWatch.Domain.Common;
using SecureWatch.Domain.Enums;

namespace SecureWatch.Domain.Entities;

public class ThreatDetection : BaseEntity, IAggregateRoot
{
    public Guid RuleId { get; set; }
    public string RuleName { get; set; } = string.Empty;
    public ThreatType ThreatType { get; set; }
    public string DetectionReason { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public int RiskScore { get; set; } // 0 - 100
    public string SourceIp { get; set; } = string.Empty;
    public string? TargetedUsername { get; set; }
    public DateTime DetectedAtUtc { get; set; } = DateTime.UtcNow;
    public string? EvidenceEventIdsJson { get; set; } // JSON array of event GUIDs
    public string RecommendedActions { get; set; } = string.Empty;
    public bool IncidentCreated { get; set; } = false;
    public Guid? IncidentId { get; set; }
    public bool IsSimulated { get; set; } = false;

    // Navigation properties
    public virtual SecurityRule? Rule { get; set; }
    public virtual Incident? Incident { get; set; }
}

