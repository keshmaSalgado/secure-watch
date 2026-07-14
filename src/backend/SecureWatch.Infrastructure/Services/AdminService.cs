using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Entities;
using SecureWatch.Infrastructure.Identity;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class AdminService : IAdminService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly SecureWatchDbContext _context;
    private readonly IAuditLogService _auditLogService;

    public AdminService(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        SecureWatchDbContext context,
        IAuditLogService auditLogService)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _context = context;
        _auditLogService = auditLogService;
    }

    public async Task<ApiResponse<List<UserDto>>> GetUsersAsync(CancellationToken ct = default)
    {
        var users = await _userManager.Users.AsNoTracking().ToListAsync(ct);
        var dtos = new List<UserDto>();

        foreach (var u in users)
        {
            var roles = await _userManager.GetRolesAsync(u);
            dtos.Add(new UserDto
            {
                Id = u.Id,
                Email = u.Email ?? string.Empty,
                FirstName = u.FirstName,
                LastName = u.LastName,
                Role = roles.FirstOrDefault() ?? "SecurityAnalyst",
                IsActive = u.IsActive,
                CreatedAtUtc = u.CreatedAtUtc,
                LastLoginUtc = u.LastLoginUtc
            });
        }

        return ApiResponse<List<UserDto>>.Ok(dtos);
    }

    public async Task<ApiResponse<UserDto>> CreateUserAsync(CreateUserDto request, CancellationToken ct = default)
    {
        var existing = await _userManager.FindByEmailAsync(request.Email);
        if (existing != null)
        {
            return ApiResponse<UserDto>.Fail("A user with this email address already exists.");
        }

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            IsActive = true,
            CreatedAtUtc = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return ApiResponse<UserDto>.Fail("Failed to create user.", result.Errors.Select(e => e.Description).ToList());
        }

        await _userManager.AddToRoleAsync(user, request.Role);
        await _auditLogService.LogAsync(user.Id, "Admin", "UserCreated", "User", user.Id, "Local", null, new { request.Email, request.Role }, ct);

        return ApiResponse<UserDto>.Ok(new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Role = request.Role,
            IsActive = user.IsActive,
            CreatedAtUtc = user.CreatedAtUtc
        }, "User created successfully.");
    }

    public async Task<ApiResponse<bool>> UpdateUserStatusAsync(string userId, UpdateUserStatusDto request, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return ApiResponse<bool>.Fail("User not found.");

        user.IsActive = request.IsActive;
        await _userManager.UpdateAsync(user);

        await _auditLogService.LogAsync(userId, "Admin", "UserStatusUpdated", "User", userId, "Local", null, new { request.IsActive }, ct);
        return ApiResponse<bool>.Ok(true, $"User status updated to {(request.IsActive ? "Active" : "Inactive")}.");
    }

    public async Task<ApiResponse<bool>> UpdateUserRoleAsync(string userId, UpdateUserRolesDto request, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return ApiResponse<bool>.Fail("User not found.");

        var currentRoles = await _userManager.GetRolesAsync(user);
        await _userManager.RemoveFromRolesAsync(user, currentRoles);
        await _userManager.AddToRoleAsync(user, request.Role);

        await _auditLogService.LogAsync(userId, "Admin", "UserRoleUpdated", "User", userId, "Local", new { OldRoles = currentRoles }, new { NewRole = request.Role }, ct);
        return ApiResponse<bool>.Ok(true, $"Role updated to {request.Role}.");
    }

    public async Task<ApiResponse<List<RoleDto>>> GetRolesAsync(CancellationToken ct = default)
    {
        var roles = await _roleManager.Roles.AsNoTracking().ToListAsync(ct);
        var dtos = roles.Select(r => new RoleDto
        {
            Name = r.Name ?? string.Empty,
            Description = r.Description,
            Permissions = RolePermissions.DefaultRolePermissions.TryGetValue(r.Name ?? "", out var p) ? p : new List<string>()
        }).ToList();

        return ApiResponse<List<RoleDto>>.Ok(dtos);
    }

    public async Task<ApiResponse<List<SecurityRuleDto>>> GetRulesAsync(CancellationToken ct = default)
    {
        var rules = await _context.SecurityRules.AsNoTracking().ToListAsync(ct);
        var dtos = rules.Select(r => new SecurityRuleDto
        {
            Id = r.Id,
            Name = r.Name,
            Code = r.Code,
            Description = r.Description,
            Category = r.Category,
            ThreatType = r.ThreatType,
            Severity = r.Severity,
            TimeWindowSeconds = r.TimeWindowSeconds,
            ThresholdCount = r.ThresholdCount,
            IsEnabled = r.IsEnabled,
            BaseRiskScore = r.BaseRiskScore
        }).ToList();

        return ApiResponse<List<SecurityRuleDto>>.Ok(dtos);
    }

    public async Task<ApiResponse<SecurityRuleDto>> UpdateRuleAsync(Guid id, UpdateSecurityRuleDto request, CancellationToken ct = default)
    {
        var rule = await _context.SecurityRules.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (rule == null) return ApiResponse<SecurityRuleDto>.Fail("Security rule not found.");

        var oldState = new { rule.Name, rule.ThresholdCount, rule.TimeWindowSeconds, rule.IsEnabled, rule.BaseRiskScore };

        rule.Name = request.Name;
        rule.Description = request.Description;
        rule.Severity = request.Severity;
        rule.TimeWindowSeconds = request.TimeWindowSeconds;
        rule.ThresholdCount = request.ThresholdCount;
        rule.IsEnabled = request.IsEnabled;
        rule.BaseRiskScore = request.BaseRiskScore;
        rule.UpdatedAtUtc = DateTime.UtcNow;

        await _context.SaveChangesAsync(ct);

        await _auditLogService.LogAsync(null, "Admin", "RuleUpdated", "SecurityRule", rule.Id.ToString(), "Local", oldState, request, ct);

        return ApiResponse<SecurityRuleDto>.Ok(new SecurityRuleDto
        {
            Id = rule.Id,
            Name = rule.Name,
            Code = rule.Code,
            Description = rule.Description,
            Category = rule.Category,
            ThreatType = rule.ThreatType,
            Severity = rule.Severity,
            TimeWindowSeconds = rule.TimeWindowSeconds,
            ThresholdCount = rule.ThresholdCount,
            IsEnabled = rule.IsEnabled,
            BaseRiskScore = rule.BaseRiskScore
        }, "Security rule updated successfully.");
    }
}

