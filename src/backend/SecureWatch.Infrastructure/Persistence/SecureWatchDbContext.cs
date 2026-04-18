using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Common;
using SecureWatch.Domain.Entities;
using SecureWatch.Infrastructure.Identity;

namespace SecureWatch.Infrastructure.Persistence;

public class SecureWatchDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>, ISecurityDbContext
{
    public SecureWatchDbContext(DbContextOptions<SecureWatchDbContext> options) : base(options)
    {
    }

    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<SecurityRule> SecurityRules => Set<SecurityRule>();
    public DbSet<ThreatDetection> ThreatDetections => Set<ThreatDetection>();
    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<IncidentEvent> IncidentEvents => Set<IncidentEvent>();
    public DbSet<IncidentNote> IncidentNotes => Set<IncidentNote>();
    public DbSet<IPReputation> IPReputations => Set<IPReputation>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<UserSession> UserSessions => Set<UserSession>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Rename Identity tables for cleaner database schema
        builder.Entity<ApplicationUser>(b =>
        {
            b.ToTable("users");
            b.HasQueryFilter(u => !u.IsDeleted);
        });

        builder.Entity<ApplicationRole>(b => b.ToTable("roles"));

        // Security Events
        builder.Entity<SecurityEvent>(entity =>
        {
            entity.ToTable("security_events");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.EventType).HasMaxLength(100).IsRequired();
            entity.Property(e => e.SourceIp).HasMaxLength(45).IsRequired();
            entity.Property(e => e.DestinationIp).HasMaxLength(45);
            entity.Property(e => e.Username).HasMaxLength(150);
            entity.Property(e => e.Description).HasMaxLength(1000);
            entity.Property(e => e.ProcessingStatus).HasMaxLength(50);

            entity.HasIndex(e => e.EventTimestampUtc);
            entity.HasIndex(e => new { e.SourceIp, e.EventTimestampUtc });
            entity.HasIndex(e => new { e.Category, e.Severity });
            entity.HasIndex(e => e.UserIdRef);

            entity.HasQueryFilter(e => !e.IsDeleted);
        });

        // Security Rules
        builder.Entity<SecurityRule>(entity =>
        {
            entity.ToTable("security_rules");
            entity.HasKey(r => r.Id);
            entity.Property(r => r.Name).HasMaxLength(150).IsRequired();
            entity.Property(r => r.Code).HasMaxLength(50).IsRequired();
            entity.HasIndex(r => r.Code).IsUnique();

            entity.HasQueryFilter(r => !r.IsDeleted);
        });

        // Threat Detections
        builder.Entity<ThreatDetection>(entity =>
        {
            entity.ToTable("threat_detections");
            entity.HasKey(t => t.Id);
            entity.Property(t => t.RuleName).HasMaxLength(150).IsRequired();
            entity.Property(t => t.SourceIp).HasMaxLength(45).IsRequired();
            entity.Property(t => t.TargetedUsername).HasMaxLength(150);

            entity.HasIndex(t => t.DetectedAtUtc);
            entity.HasIndex(t => t.SourceIp);
            entity.HasIndex(t => t.RiskScore);

            entity.HasOne(t => t.Rule)
                .WithMany(r => r.ThreatDetections)
                .HasForeignKey(t => t.RuleId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(t => t.Incident)
                .WithMany(i => i.ThreatDetections)
                .HasForeignKey(t => t.IncidentId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasQueryFilter(t => !t.IsDeleted);
        });

        // Incidents
        builder.Entity<Incident>(entity =>
        {
            entity.ToTable("incidents");
            entity.HasKey(i => i.Id);
            entity.Property(i => i.IncidentCode).HasMaxLength(50).IsRequired();
            entity.HasIndex(i => i.IncidentCode).IsUnique();
            entity.Property(i => i.Title).HasMaxLength(200).IsRequired();
            entity.Property(i => i.Description).HasMaxLength(2000);
            entity.Property(i => i.SourceIp).HasMaxLength(45);

            entity.HasIndex(i => new { i.Status, i.Severity });
            entity.HasIndex(i => i.CreatedAtUtc);
            entity.HasIndex(i => i.AssignedAnalystId);

            entity.HasQueryFilter(i => !i.IsDeleted);
        });

        // Incident Events junction
        builder.Entity<IncidentEvent>(entity =>
        {
            entity.ToTable("incident_events");
            entity.HasKey(ie => ie.Id);

            entity.HasOne(ie => ie.Incident)
                .WithMany(i => i.IncidentEvents)
                .HasForeignKey(ie => ie.IncidentId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(ie => ie.SecurityEvent)
                .WithMany(se => se.IncidentEvents)
                .HasForeignKey(ie => ie.SecurityEventId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(ie => new { ie.IncidentId, ie.SecurityEventId }).IsUnique();
        });

        // Incident Notes
        builder.Entity<IncidentNote>(entity =>
        {
            entity.ToTable("incident_notes");
            entity.HasKey(n => n.Id);
            entity.Property(n => n.AuthorName).HasMaxLength(150).IsRequired();
            entity.Property(n => n.NoteText).HasMaxLength(3000).IsRequired();

            entity.HasOne(n => n.Incident)
                .WithMany(i => i.Notes)
                .HasForeignKey(n => n.IncidentId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // IP Reputation
        builder.Entity<IPReputation>(entity =>
        {
            entity.ToTable("ip_reputations");
            entity.HasKey(ip => ip.IpAddress);
            entity.Property(ip => ip.IpAddress).HasMaxLength(45);
            entity.Property(ip => ip.CountryCode).HasMaxLength(10);
            entity.Property(ip => ip.CountryName).HasMaxLength(100);
            entity.Property(ip => ip.Isp).HasMaxLength(150);

            entity.HasIndex(ip => ip.ReputationScore);
            entity.HasIndex(ip => ip.IsMalicious);
        });

        // Alerts
        builder.Entity<Alert>(entity =>
        {
            entity.ToTable("alerts");
            entity.HasKey(a => a.Id);
            entity.Property(a => a.Title).HasMaxLength(200).IsRequired();
            entity.Property(a => a.Message).HasMaxLength(1000).IsRequired();

            entity.HasOne(a => a.Incident)
                .WithMany(i => i.Alerts)
                .HasForeignKey(a => a.IncidentId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasQueryFilter(a => !a.IsDeleted);
        });

        // Audit Logs (append only)
        builder.Entity<AuditLog>(entity =>
        {
            entity.ToTable("audit_logs");
            entity.HasKey(a => a.Id);
            entity.Property(a => a.Username).HasMaxLength(150).IsRequired();
            entity.Property(a => a.Action).HasMaxLength(100).IsRequired();
            entity.Property(a => a.EntityName).HasMaxLength(100).IsRequired();
            entity.Property(a => a.IpAddress).HasMaxLength(45);

            entity.HasIndex(a => a.TimestampUtc);
            entity.HasIndex(a => new { a.UserId, a.Action });
        });

        // Refresh Tokens
        builder.Entity<RefreshToken>(entity =>
        {
            entity.ToTable("refresh_tokens");
            entity.HasKey(r => r.Id);
            entity.Property(r => r.TokenHash).HasMaxLength(256).IsRequired();
            entity.HasIndex(r => r.TokenHash).IsUnique();
            entity.HasIndex(r => r.UserId);
        });

        // User Sessions
        builder.Entity<UserSession>(entity =>
        {
            entity.ToTable("user_sessions");
            entity.HasKey(s => s.Id);
            entity.Property(s => s.IpAddress).HasMaxLength(45).IsRequired();
            entity.HasIndex(s => new { s.UserId, s.IsActive });
        });
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        foreach (var entry in ChangeTracker.Entries<BaseEntity>())
        {
            if (entry.State == EntityState.Added)
            {
                entry.Entity.CreatedAtUtc = DateTime.UtcNow;
            }
            else if (entry.State == EntityState.Modified)
            {
                entry.Entity.UpdatedAtUtc = DateTime.UtcNow;
            }
        }

        return base.SaveChangesAsync(cancellationToken);
    }
}
