using SecureWatch.Domain.Common;

namespace SecureWatch.Domain.Entities;

public class UserSession : BaseEntity
{
    public string UserId { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string? UserAgent { get; set; }
    public DateTime LoginTimeUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastActivityUtc { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
}

