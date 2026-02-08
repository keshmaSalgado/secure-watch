using SecureWatch.Domain.Common;
using SecureWatch.Domain.Enums;

namespace SecureWatch.Domain.Entities;

public class SecurityRule : BaseEntity, IAggregateRoot
{
    public string Name { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public EventCategory Category { get; set; }
    public ThreatType ThreatType { get; set; }
    public SeverityLevel Severity { get; set; }
    public int TimeWindowSeconds { get; set; } = 60;
    public int ThresholdCount { get; set; } = 5;
    public bool IsEnabled { get; set; } = true;
    public string? ConditionExpression { get; set; }
    public string? ParametersJson { get; set; }
    public int BaseRiskScore { get; set; } = 50;

    // Navigation properties
    public virtual ICollection<ThreatDetection> ThreatDetections { get; set; } = new List<ThreatDetection>();
}

