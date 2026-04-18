using Microsoft.AspNetCore.Identity;

namespace SecureWatch.Infrastructure.Identity;

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string? Department { get; set; }
    public bool IsActive { get; set; } = true;
    public bool IsDeleted { get; set; } = false;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAtUtc { get; set; }
    public DateTime? LastLoginUtc { get; set; }
}

public class ApplicationRole : IdentityRole
{
    public string Description { get; set; } = string.Empty;
    public bool IsSystemRole { get; set; } = true;
}

