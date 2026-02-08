using SecureWatch.Domain.Common;

namespace SecureWatch.Domain.Entities;

public class AuditLog : BaseEntity, IAggregateRoot
{
    public string? UserId { get; set; }
    public string Username { get; set; } = "System";
    public string Action { get; set; } = string.Empty;
    public string EntityName { get; set; } = string.Empty;
    public string? EntityId { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? OldValuesJson { get; set; }
    public string? NewValuesJson { get; set; }
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
}

