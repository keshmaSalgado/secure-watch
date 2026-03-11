using SecureWatch.Domain.Enums;

namespace SecureWatch.Application.DTOs;

public class ThreatDetectionDto
{
    public Guid Id { get; set; }
    public Guid RuleId { get; set; }
    public string RuleName { get; set; } = string.Empty;
    public ThreatType ThreatType { get; set; }
    public string ThreatTypeName => ThreatType.ToString();
    public string DetectionReason { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public string SeverityName => Severity.ToString();
    public int RiskScore { get; set; }
    public string RiskLevel => RiskScore switch
    {
        >= 80 => "Critical",
        >= 60 => "High",
        >= 30 => "Medium",
        _ => "Low"
    };
    public string SourceIp { get; set; } = string.Empty;
    public string? TargetedUsername { get; set; }
    public DateTime DetectedAtUtc { get; set; }
    public List<Guid> EvidenceEventIds { get; set; } = new();
    public string RecommendedActions { get; set; } = string.Empty;
    public bool IncidentCreated { get; set; }
    public Guid? IncidentId { get; set; }
    public bool IsSimulated { get; set; }
}

public class ThreatQueryParameters
{
    public int PageIndex { get; set; } = 1;
    public int PageSize { get; set; } = 20;
    public SeverityLevel? Severity { get; set; }
    public ThreatType? ThreatType { get; set; }
    public string? SourceIp { get; set; }
    public int? MinRiskScore { get; set; }
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
}

public class ThreatStatisticsDto
{
    public int TotalThreatsDetected { get; set; }
    public int CriticalThreats { get; set; }
    public int HighThreats { get; set; }
    public double AverageRiskScore { get; set; }
    public Dictionary<string, int> ThreatsByType { get; set; } = new();
    public List<TopThreatIpDto> TopThreatIps { get; set; } = new();
}

public class TopThreatIpDto
{
    public string IpAddress { get; set; } = string.Empty;
    public int ThreatCount { get; set; }
    public int MaxRiskScore { get; set; }
    public string? Country { get; set; }
}

