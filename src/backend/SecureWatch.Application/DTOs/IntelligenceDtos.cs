namespace SecureWatch.Application.DTOs;

public class IpReputationDto
{
    public string IpAddress { get; set; } = string.Empty;
    public int ReputationScore { get; set; } // 0 - 100
    public bool IsMalicious { get; set; }
    public bool IsTor { get; set; }
    public bool IsVpnOrProxy { get; set; }
    public string? CountryCode { get; set; }
    public string? CountryName { get; set; }
    public string? Region { get; set; }
    public string? City { get; set; }
    public string? Isp { get; set; }
    public string? Asn { get; set; }
    public int TotalEventsRecorded { get; set; }
    public DateTime LastCheckedAtUtc { get; set; }
    public List<SecurityEventDto> RecentEvents { get; set; } = new();
    public List<ThreatDetectionDto> RecentThreats { get; set; } = new();
}

