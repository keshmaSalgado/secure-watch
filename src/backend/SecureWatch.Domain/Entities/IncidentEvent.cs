using SecureWatch.Domain.Common;

namespace SecureWatch.Domain.Entities;

public class IncidentEvent : BaseEntity
{
    public Guid IncidentId { get; set; }
    public Guid SecurityEventId { get; set; }
    public DateTime LinkedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual Incident Incident { get; set; } = null!;
    public virtual SecurityEvent SecurityEvent { get; set; } = null!;
}

