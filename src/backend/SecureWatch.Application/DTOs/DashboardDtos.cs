namespace SecureWatch.Application.DTOs;

public class DashboardOverviewDto
{
    public int TotalEvents { get; set; }
    public int TotalThreatsDetected { get; set; }
    public int CriticalIncidents { get; set; }
    public int ActiveIncidents { get; set; }
    public int FailedLoginAttempts { get; set; }
    public int SuspiciousIpCount { get; set; }
    public double OverallRiskScore { get; set; }
    public string OverallRiskLevel => OverallRiskScore switch
    {
        >= 80 => "Critical",
        >= 60 => "High",
        >= 30 => "Medium",
        _ => "Low"
    };
    public List<SecurityEventDto> RecentEvents { get; set; } = new();
    public List<IncidentDto> RecentIncidents { get; set; } = new();
}

public class ThreatTrendDto
{
    public string TimeLabel { get; set; } = string.Empty;
    public int EventCount { get; set; }
    public int ThreatCount { get; set; }
    public int FailedLogins { get; set; }
}

public class RiskDistributionDto
{
    public int LowCount { get; set; }
    public int MediumCount { get; set; }
    public int HighCount { get; set; }
    public int CriticalCount { get; set; }
}

