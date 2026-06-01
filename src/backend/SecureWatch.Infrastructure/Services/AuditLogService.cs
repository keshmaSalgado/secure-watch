using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SecureWatch.Application.Common;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Entities;
using SecureWatch.Infrastructure.Persistence;

namespace SecureWatch.Infrastructure.Services;

public class AuditLogService : IAuditLogService
{
    private readonly SecureWatchDbContext _context;

    public AuditLogService(SecureWatchDbContext context)
    {
        _context = context;
    }

    public async Task LogAsync(
        string? userId,
        string username,
        string action,
        string entityName,
        string? entityId,
        string? ipAddress,
        object? oldValues = null,
        object? newValues = null,
        CancellationToken ct = default)
    {
        var log = new AuditLog
        {
            UserId = userId,
            Username = username,
            Action = action,
            EntityName = entityName,
            EntityId = entityId,
            IpAddress = ipAddress,
            OldValuesJson = oldValues != null ? JsonSerializer.Serialize(oldValues) : null,
            NewValuesJson = newValues != null ? JsonSerializer.Serialize(newValues) : null,
            TimestampUtc = DateTime.UtcNow
        };

        await _context.AuditLogs.AddAsync(log, ct);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<ApiResponse<PagedResult<AuditLogDto>>> GetAuditLogsAsync(
        int pageIndex,
        int pageSize,
        string? username = null,
        string? action = null,
        CancellationToken ct = default)
    {
        var query = _context.AuditLogs.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(username))
        {
            query = query.Where(a => a.Username.ToLower().Contains(username.ToLower()));
        }

        if (!string.IsNullOrWhiteSpace(action))
        {
            query = query.Where(a => a.Action.ToLower().Contains(action.ToLower()));
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(a => a.TimestampUtc)
            .Skip((pageIndex - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new AuditLogDto
            {
                Id = a.Id,
                UserId = a.UserId,
                Username = a.Username,
                Action = a.Action,
                EntityName = a.EntityName,
                EntityId = a.EntityId,
                IpAddress = a.IpAddress,
                OldValuesJson = a.OldValuesJson,
                NewValuesJson = a.NewValuesJson,
                TimestampUtc = a.TimestampUtc
            })
            .ToListAsync(ct);

        var pagedResult = new PagedResult<AuditLogDto>(items, total, pageIndex, pageSize);
        return ApiResponse<PagedResult<AuditLogDto>>.Ok(pagedResult);
    }
}

