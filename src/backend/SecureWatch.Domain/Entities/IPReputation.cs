namespace SecureWatch.Domain.Entities;

public class IPReputation
{
    public string IpAddress { get; set; } = string.Empty; // Primary Key
    public int ReputationScore { get; set; } // 0 (Safe) - 100 (Hostile / Malicious)
    public bool IsMalicious { get; set; } = false;
    public bool IsTor { get; set; } = false;
    public bool IsVpnOrProxy { get; set; } = false;
    public string? CountryCode { get; set; }
    public string? CountryName { get; set; }
    public string? Region { get; set; }
    public string? City { get; set; }
    public string? Isp { get; set; }
    public string? Asn { get; set; }
    public int TotalEventsRecorded { get; set; } = 0;
    public DateTime LastCheckedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

