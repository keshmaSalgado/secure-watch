using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Api.Controllers;

[Authorize]
public class AdminController : BaseApiController
{
    private readonly IAdminService _adminService;
    private readonly IAuditLogService _auditLogService;

    public AdminController(IAdminService adminService, IAuditLogService auditLogService)
    {
        _adminService = adminService;
        _auditLogService = auditLogService;
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers(CancellationToken ct)
    {
        var result = await _adminService.GetUsersAsync(ct);
        return HandleResult(result);
    }

    [HttpPost("users")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserDto request, CancellationToken ct)
    {
        var result = await _adminService.CreateUserAsync(request, ct);
        return HandleResult(result);
    }

    [HttpPut("users/{id}/status")]
    public async Task<IActionResult> UpdateUserStatus(string id, [FromBody] UpdateUserStatusDto request, CancellationToken ct)
    {
        var result = await _adminService.UpdateUserStatusAsync(id, request, ct);
        return HandleResult(result);
    }

    [HttpPut("users/{id}/roles")]
    public async Task<IActionResult> UpdateUserRole(string id, [FromBody] UpdateUserRolesDto request, CancellationToken ct)
    {
        var result = await _adminService.UpdateUserRoleAsync(id, request, ct);
        return HandleResult(result);
    }

    [HttpGet("roles")]
    public async Task<IActionResult> GetRoles(CancellationToken ct)
    {
        var result = await _adminService.GetRolesAsync(ct);
        return HandleResult(result);
    }

    [HttpGet("rules")]
    public async Task<IActionResult> GetRules(CancellationToken ct)
    {
        var result = await _adminService.GetRulesAsync(ct);
        return HandleResult(result);
    }

    [HttpPut("rules/{id:guid}")]
    public async Task<IActionResult> UpdateRule(Guid id, [FromBody] UpdateSecurityRuleDto request, CancellationToken ct)
    {
        var result = await _adminService.UpdateRuleAsync(id, request, ct);
        return HandleResult(result);
    }

    [HttpGet("audit-logs")]
    public async Task<IActionResult> GetAuditLogs(
        [FromQuery] int pageIndex = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? username = null,
        [FromQuery] string? action = null,
        CancellationToken ct = default)
    {
        var result = await _auditLogService.GetAuditLogsAsync(pageIndex, pageSize, username, action, ct);
        return HandleResult(result);
    }
}

