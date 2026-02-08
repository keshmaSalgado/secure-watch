using SecureWatch.Domain.Common;

namespace SecureWatch.Domain.Entities;

public class IncidentNote : BaseEntity
{
    public Guid IncidentId { get; set; }
    public string AuthorId { get; set; } = string.Empty;
    public string AuthorName { get; set; } = string.Empty;
    public string NoteText { get; set; } = string.Empty;
    public bool IsInternalOnly { get; set; } = false;

    // Navigation properties
    public virtual Incident Incident { get; set; } = null!;
}

