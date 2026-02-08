using SecureWatch.Domain.Common;
using SecureWatch.Domain.Enums;

namespace SecureWatch.Domain.Entities;

public class Incident : BaseEntity, IAggregateRoot
{
    public string IncidentCode { get; set; } = string.Empty; // e.g., SEC-2026-0001
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public int RiskScore { get; set; } // 0 - 100
    public IncidentStatus Status { get; set; } = IncidentStatus.Open;
    public string? AssignedAnalystId { get; set; }
    public string? AssignedAnalystName { get; set; }
    public string? SourceIp { get; set; }
    public DateTime? ResolvedAtUtc { get; set; }
    public string? ResolutionSummary { get; set; }
    public string? RootCause { get; set; }
    public bool IsSimulated { get; set; } = false;

    // Navigation properties
    public virtual ICollection<IncidentEvent> IncidentEvents { get; set; } = new List<IncidentEvent>();
    public virtual ICollection<IncidentNote> Notes { get; set; } = new List<IncidentNote>();
    public virtual ICollection<ThreatDetection> ThreatDetections { get; set; } = new List<ThreatDetection>();
    public virtual ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}

