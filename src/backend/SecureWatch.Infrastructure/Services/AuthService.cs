using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Entities;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Identity;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly IJwtTokenGenerator _jwtGenerator;
    private readonly SecureWatchDbContext _context;
    private readonly IAuditLogService _auditLogService;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        IJwtTokenGenerator jwtGenerator,
        SecureWatchDbContext context,
        IAuditLogService auditLogService,
        ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _jwtGenerator = jwtGenerator;
        _context = context;
        _auditLogService = auditLogService;
        _logger = logger;
    }

    public async Task<ApiResponse<LoginResponseDto>> LoginAsync(LoginRequestDto request, string ipAddress, CancellationToken ct = default)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null || !user.IsActive)
        {
            await _auditLogService.LogAsync(null, request.Email, "LoginFailed", "User", null, ipAddress, null, new { Reason = "User not found or inactive" }, ct);
            return ApiResponse<LoginResponseDto>.Fail("Invalid credentials or account is deactivated.");
        }

        // Account lockout check
        if (await _userManager.IsLockedOutAsync(user))
        {
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            await _auditLogService.LogAsync(user.Id, user.Email!, "LoginBlockedLockedOut", "User", user.Id, ipAddress, null, new { LockoutEnd = lockoutEnd }, ct);
            return ApiResponse<LoginResponseDto>.Fail($"Account is locked due to repeated failed attempts. Try again after {lockoutEnd:g} UTC.");
        }

        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!isPasswordValid)
        {
            await _userManager.AccessFailedAsync(user);
            await _auditLogService.LogAsync(user.Id, user.Email!, "LoginFailed", "User", user.Id, ipAddress, null, new { Reason = "Invalid password", FailedCount = user.AccessFailedCount }, ct);
            return ApiResponse<LoginResponseDto>.Fail("Invalid credentials.");
        }

        // Reset lockout on successful login
        await _userManager.ResetAccessFailedCountAsync(user);
        user.LastLoginUtc = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Fetch user roles and permissions
        var roles = await _userManager.GetRolesAsync(user);
        var primaryRole = roles.FirstOrDefault() ?? RolePermissions.SecurityAnalyst;
        var permissions = RolePermissions.DefaultRolePermissions.TryGetValue(primaryRole, out var perms)
            ? perms
            : new List<string>();

        // Generate tokens
        var (accessToken, expiresAtUtc) = _jwtGenerator.GenerateAccessToken(user, primaryRole, permissions);
        var rawRefreshToken = _jwtGenerator.GenerateRefreshToken();
        var hashedRefreshToken = HashToken(rawRefreshToken);

        var refreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = hashedRefreshToken,
            CreatedByIp = ipAddress,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };

        await _context.RefreshTokens.AddAsync(refreshTokenEntity, ct);

        // Record UserSession
        await _context.UserSessions.AddAsync(new UserSession
        {
            UserId = user.Id,
            Username = user.Email!,
            IpAddress = ipAddress,
            LoginTimeUtc = DateTime.UtcNow,
            LastActivityUtc = DateTime.UtcNow,
            IsActive = true
        }, ct);

        await _context.SaveChangesAsync(ct);

        await _auditLogService.LogAsync(user.Id, user.Email!, "LoginSuccess", "User", user.Id, ipAddress, null, new { Role = primaryRole }, ct);

        var profile = new UserProfileDto
        {
            Id = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Role = primaryRole,
            Permissions = permissions,
            CreatedAtUtc = user.CreatedAtUtc
        };

        return ApiResponse<LoginResponseDto>.Ok(new LoginResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = rawRefreshToken,
            ExpiresAtUtc = expiresAtUtc,
            User = profile
        }, "Login successful.");
    }

    public async Task<ApiResponse<UserProfileDto>> RegisterAsync(RegisterRequestDto request, CancellationToken ct = default)
    {
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            return ApiResponse<UserProfileDto>.Fail("A user with this email already exists.");
        }

        var validRoles = new[] { RolePermissions.SuperAdmin, RolePermissions.SecurityAdmin, RolePermissions.SecurityAnalyst, RolePermissions.Auditor };
        var roleToAssign = validRoles.Contains(request.Role) ? request.Role : RolePermissions.SecurityAnalyst;

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
            var errors = result.Errors.Select(e => e.Description).ToList();
            return ApiResponse<UserProfileDto>.Fail("Registration failed.", errors);
        }

        await _userManager.AddToRoleAsync(user, roleToAssign);

        await _auditLogService.LogAsync(user.Id, user.Email, "UserRegistered", "User", user.Id, "Local", null, new { Role = roleToAssign }, ct);

        var permissions = RolePermissions.DefaultRolePermissions.TryGetValue(roleToAssign, out var perms) ? perms : new List<string>();

        var profile = new UserProfileDto
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Role = roleToAssign,
            Permissions = permissions,
            CreatedAtUtc = user.CreatedAtUtc
        };

        return ApiResponse<UserProfileDto>.Ok(profile, "User registered successfully.");
    }

    public async Task<ApiResponse<LoginResponseDto>> RefreshTokenAsync(RefreshTokenRequestDto request, string ipAddress, CancellationToken ct = default)
    {
        var tokenHash = HashToken(request.RefreshToken);
        var existingToken = await _context.RefreshTokens.FirstOrDefaultAsync(r => r.TokenHash == tokenHash, ct);

        if (existingToken == null)
        {
            return ApiResponse<LoginResponseDto>.Fail("Invalid refresh token.");
        }

        // Replay attack detection: if token is already revoked, revoke ALL tokens for this user!
        if (existingToken.IsRevoked)
        {
            _logger.LogWarning("Replay attack detected for user {UserId}. Revoking all refresh tokens.", existingToken.UserId);
            var allTokens = await _context.RefreshTokens.Where(r => r.UserId == existingToken.UserId && r.RevokedAtUtc == null).ToListAsync(ct);
            foreach (var t in allTokens)
            {
                t.RevokedAtUtc = DateTime.UtcNow;
            }
            await _context.SaveChangesAsync(ct);
            await _auditLogService.LogAsync(existingToken.UserId, "SecuritySystem", "ReplayAttackDetected", "RefreshToken", existingToken.Id.ToString(), ipAddress, null, null, ct);
            return ApiResponse<LoginResponseDto>.Fail("Security violation: Token was already revoked. Please log in again.");
        }

        if (existingToken.IsExpired)
        {
            return ApiResponse<LoginResponseDto>.Fail("Refresh token has expired. Please log in again.");
        }

        var user = await _userManager.FindByIdAsync(existingToken.UserId);
        if (user == null || !user.IsActive)
        {
            return ApiResponse<LoginResponseDto>.Fail("User account no longer active.");
        }

        // Token rotation: Revoke current token
        var newRawRefreshToken = _jwtGenerator.GenerateRefreshToken();
        var newHashedRefreshToken = HashToken(newRawRefreshToken);

        existingToken.RevokedAtUtc = DateTime.UtcNow;
        existingToken.ReplacedByToken = newHashedRefreshToken;

        var newRefreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = newHashedRefreshToken,
            CreatedByIp = ipAddress,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };

        await _context.RefreshTokens.AddAsync(newRefreshTokenEntity, ct);
        await _context.SaveChangesAsync(ct);

        var roles = await _userManager.GetRolesAsync(user);
        var primaryRole = roles.FirstOrDefault() ?? RolePermissions.SecurityAnalyst;
        var permissions = RolePermissions.DefaultRolePermissions.TryGetValue(primaryRole, out var perms) ? perms : new List<string>();

        var (accessToken, expiresAtUtc) = _jwtGenerator.GenerateAccessToken(user, primaryRole, permissions);

        var profile = new UserProfileDto
        {
            Id = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Role = primaryRole,
            Permissions = permissions,
            CreatedAtUtc = user.CreatedAtUtc
        };

        return ApiResponse<LoginResponseDto>.Ok(new LoginResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = newRawRefreshToken,
            ExpiresAtUtc = expiresAtUtc,
            User = profile
        }, "Token refreshed successfully.");
    }

    public async Task<ApiResponse<bool>> LogoutAsync(string userId, CancellationToken ct = default)
    {
        var activeTokens = await _context.RefreshTokens
            .Where(r => r.UserId == userId && r.RevokedAtUtc == null)
            .ToListAsync(ct);

        foreach (var t in activeTokens)
        {
            t.RevokedAtUtc = DateTime.UtcNow;
        }

        var activeSessions = await _context.UserSessions
            .Where(s => s.UserId == userId && s.IsActive)
            .ToListAsync(ct);

        foreach (var s in activeSessions)
        {
            s.IsActive = false;
        }

        await _context.SaveChangesAsync(ct);
        await _auditLogService.LogAsync(userId, "System", "UserLogout", "User", userId, "Local", null, null, ct);

        return ApiResponse<bool>.Ok(true, "Logged out successfully.");
    }

    public async Task<ApiResponse<UserProfileDto>> GetCurrentUserProfileAsync(string userId, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return ApiResponse<UserProfileDto>.Fail("User not found.");
        }

        var roles = await _userManager.GetRolesAsync(user);
        var primaryRole = roles.FirstOrDefault() ?? RolePermissions.SecurityAnalyst;
        var permissions = RolePermissions.DefaultRolePermissions.TryGetValue(primaryRole, out var perms) ? perms : new List<string>();

        return ApiResponse<UserProfileDto>.Ok(new UserProfileDto
        {
            Id = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Role = primaryRole,
            Permissions = permissions,
            CreatedAtUtc = user.CreatedAtUtc
        });
    }

    public async Task<ApiResponse<bool>> ChangePasswordAsync(string userId, ChangePasswordDto request, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return ApiResponse<bool>.Fail("User not found.");
        }

        var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description).ToList();
            return ApiResponse<bool>.Fail("Failed to change password.", errors);
        }

        await _auditLogService.LogAsync(user.Id, user.Email!, "PasswordChanged", "User", user.Id, "Local", null, null, ct);
        return ApiResponse<bool>.Ok(true, "Password changed successfully.");
    }

    private static string HashToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes);
    }
}

