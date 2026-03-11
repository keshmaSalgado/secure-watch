using Microsoft.EntityFrameworkCore;
using SecureWatch.Domain.Entities;

namespace SecureWatch.Application.Interfaces;

public interface ISecurityDbContext
{
    DbSet<SecurityEvent> SecurityEvents { get; }
    DbSet<SecurityRule> SecurityRules { get; }
    DbSet<ThreatDetection> ThreatDetections { get; }
    DbSet<Incident> Incidents { get; }
    DbSet<IncidentEvent> IncidentEvents { get; }
    DbSet<IncidentNote> IncidentNotes { get; }
    DbSet<IPReputation> IPReputations { get; }
    DbSet<Alert> Alerts { get; }
    DbSet<AuditLog> AuditLogs { get; }
    DbSet<RefreshToken> RefreshTokens { get; }
    DbSet<UserSession> UserSessions { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

