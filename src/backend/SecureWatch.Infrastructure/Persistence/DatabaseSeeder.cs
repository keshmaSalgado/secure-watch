using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureWatch.Domain.Entities;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Identity;

namespace SecureWatch.Infrastructure.Persistence;

public class DatabaseSeeder
{
    private readonly SecureWatchDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ILogger<DatabaseSeeder> _logger;

    public DatabaseSeeder(
        SecureWatchDbContext context,
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        ILogger<DatabaseSeeder> logger)
    {
        _context = context;
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    public async Task SeedAsync()
    {
        try
        {
            await SeedRolesAndPermissionsAsync();
            await SeedUsersAsync();
            await SeedSecurityRulesAsync();
            await SeedIpReputationsAsync();
            await SeedSecurityEventsAndIncidentsAsync();
            _logger.LogInformation("Database seeded successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while seeding the database.");
            throw;
        }
    }

    private async Task SeedRolesAndPermissionsAsync()
    {
        foreach (var rolePair in RolePermissions.DefaultRolePermissions)
        {
            var roleName = rolePair.Key;
            var roleExists = await _roleManager.RoleExistsAsync(roleName);
            if (!roleExists)
            {
                var role = new ApplicationRole
                {
                    Name = roleName,
                    NormalizedName = roleName.ToUpperInvariant(),
                    Description = $"{roleName} role with predefined cybersecurity permissions.",
                    IsSystemRole = true
                };
                await _roleManager.CreateAsync(role);

                foreach (var permission in rolePair.Value)
                {
                    await _roleManager.AddClaimAsync(role, new System.Security.Claims.Claim("permission", permission));
                }
            }
        }
    }

    private async Task SeedUsersAsync()
    {
        var usersToSeed = new List<(string Email, string FirstName, string LastName, string Role, string Department)>
        {
            ("admin@securewatch.local", "John", "Vance", RolePermissions.SuperAdmin, "Security Leadership"),
            ("secadmin@securewatch.local", "Sarah", "Connor", RolePermissions.SecurityAdmin, "SecOps Engineering"),
            ("analyst@securewatch.local", "Alex", "Rivera", RolePermissions.SecurityAnalyst, "SOC Team Alpha"),
            ("auditor@securewatch.local", "Marcus", "Reed", RolePermissions.Auditor, "Compliance & Governance")
        };

        const string demoPassword = "SecureWatch@2026!";

        foreach (var (email, firstName, lastName, role, department) in usersToSeed)
        {
            var existingUser = await _userManager.FindByEmailAsync(email);
            if (existingUser == null)
            {
                var user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    FirstName = firstName,
                    LastName = lastName,
                    Department = department,
                    IsActive = true,
                    CreatedAtUtc = DateTime.UtcNow
                };

                var createResult = await _userManager.CreateAsync(user, demoPassword);
                if (createResult.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, role);
                }
            }
        }
    }

    private async Task SeedSecurityRulesAsync()
    {
        if (await _context.SecurityRules.AnyAsync()) return;

        var rules = new List<SecurityRule>
        {
            new()
            {
                Name = "5 Failed Logins within 1 Minute",
                Code = "RULE-01-BRUTE-FAST",
                Description = "Detects rapid password guessing attacks by monitoring 5 consecutive authentication failures from an IP within 60 seconds.",
                Category = EventCategory.FailedLogin,
                ThreatType = ThreatType.BruteForce,
                Severity = SeverityLevel.High,
                TimeWindowSeconds = 60,
                ThresholdCount = 5,
                BaseRiskScore = 75,
                IsEnabled = true
            },
            new()
            {
                Name = "20 Failed Logins within 2 Minutes (Distributed/Aggressive)",
                Code = "RULE-02-BRUTE-AGGRESSIVE",
                Description = "Identifies aggressive brute force or automated credential spray with 20 or more failed attempts within 120 seconds.",
                Category = EventCategory.FailedLogin,
                ThreatType = ThreatType.RapidFailures,
                Severity = SeverityLevel.Critical,
                TimeWindowSeconds = 120,
                ThresholdCount = 20,
                BaseRiskScore = 90,
                IsEnabled = true
            },
            new()
            {
                Name = "Successful Login Following Repeated Failures",
                Code = "RULE-03-SUCCESS-AFTER-FAIL",
                Description = "Flags potential credential compromise where a successful authentication occurs immediately after repeated failures on the same account.",
                Category = EventCategory.SuccessfulLogin,
                ThreatType = ThreatType.SuccessAfterFailures,
                Severity = SeverityLevel.High,
                TimeWindowSeconds = 180,
                ThresholdCount = 3,
                BaseRiskScore = 80,
                IsEnabled = true
            },
            new()
            {
                Name = "Multiple Accounts Accessed from Single IP",
                Code = "RULE-04-MULTI-ACCOUNT-SPRAY",
                Description = "Detects credential spraying attacks attempting to authenticate against 3 or more distinct user accounts from a single IP address.",
                Category = EventCategory.FailedLogin,
                ThreatType = ThreatType.MultiAccountTargeting,
                Severity = SeverityLevel.High,
                TimeWindowSeconds = 300,
                ThresholdCount = 3,
                BaseRiskScore = 85,
                IsEnabled = true
            },
            new()
            {
                Name = "Login from Known Malicious IP",
                Code = "RULE-05-MALICIOUS-IP",
                Description = "Triggers immediate critical detection whenever incoming authentication traffic originates from an IP marked hostile in threat feeds.",
                Category = EventCategory.FailedLogin,
                ThreatType = ThreatType.MaliciousIpActivity,
                Severity = SeverityLevel.Critical,
                TimeWindowSeconds = 60,
                ThresholdCount = 1,
                BaseRiskScore = 95,
                IsEnabled = true
            },
            new()
            {
                Name = "Unusual Login Time Anomaly",
                Code = "RULE-06-UNUSUAL-TIME",
                Description = "Flags access requests taking place outside normal business operating hours (between 01:00 and 05:00 UTC) for privileged roles.",
                Category = EventCategory.SuccessfulLogin,
                ThreatType = ThreatType.UnusualLoginTime,
                Severity = SeverityLevel.Medium,
                TimeWindowSeconds = 3600,
                ThresholdCount = 1,
                BaseRiskScore = 45,
                IsEnabled = true
            },
            new()
            {
                Name = "Multiple Login Attempts from Unfamiliar Locations",
                Code = "RULE-07-GEO-ANOMALY",
                Description = "Identifies geographically improbable travel or access attempts originating from foreign/unusual ASNs within short intervals.",
                Category = EventCategory.SuccessfulLogin,
                ThreatType = ThreatType.UnfamiliarLocation,
                Severity = SeverityLevel.High,
                TimeWindowSeconds = 600,
                ThresholdCount = 2,
                BaseRiskScore = 70,
                IsEnabled = true
            }
        };

        await _context.SecurityRules.AddRangeAsync(rules);
        await _context.SaveChangesAsync();
    }

    private async Task SeedIpReputationsAsync()
    {
        if (await _context.IPReputations.AnyAsync()) return;

        var ipProfiles = new List<IPReputation>
        {
            new()
            {
                IpAddress = "198.51.100.42",
                ReputationScore = 95,
                IsMalicious = true,
                IsTor = false,
                IsVpnOrProxy = true,
                CountryCode = "RU",
                CountryName = "Russian Federation",
                Region = "Moscow",
                City = "Moscow",
                Isp = "Mirax Hosting Network",
                Asn = "AS48201",
                TotalEventsRecorded = 124,
                LastCheckedAtUtc = DateTime.UtcNow
            },
            new()
            {
                IpAddress = "185.220.101.5",
                ReputationScore = 85,
                IsMalicious = true,
                IsTor = true,
                IsVpnOrProxy = true,
                CountryCode = "DE",
                CountryName = "Germany",
                Region = "Hesse",
                City = "Frankfurt am Main",
                Isp = "Tor Exit Node Association",
                Asn = "AS200651",
                TotalEventsRecorded = 89,
                LastCheckedAtUtc = DateTime.UtcNow
            },
            new()
            {
                IpAddress = "203.0.113.88",
                ReputationScore = 65,
                IsMalicious = false,
                IsTor = false,
                IsVpnOrProxy = true,
                CountryCode = "NL",
                CountryName = "Netherlands",
                Region = "North Holland",
                City = "Amsterdam",
                Isp = "NordVPN Transit",
                Asn = "AS13335",
                TotalEventsRecorded = 34,
                LastCheckedAtUtc = DateTime.UtcNow
            },
            new()
            {
                IpAddress = "192.168.1.100",
                ReputationScore = 5,
                IsMalicious = false,
                IsTor = false,
                IsVpnOrProxy = false,
                CountryCode = "US",
                CountryName = "United States",
                Region = "California",
                City = "San Jose",
                Isp = "Corporate Internal Subnet",
                Asn = "AS15169",
                TotalEventsRecorded = 520,
                LastCheckedAtUtc = DateTime.UtcNow
            },
            new()
            {
                IpAddress = "10.0.0.15",
                ReputationScore = 0,
                IsMalicious = false,
                IsTor = false,
                IsVpnOrProxy = false,
                CountryCode = "US",
                CountryName = "United States",
                Region = "California",
                City = "San Francisco",
                Isp = "SecureWatch HQ LAN",
                Asn = "AS15169",
                TotalEventsRecorded = 830,
                LastCheckedAtUtc = DateTime.UtcNow
            }
        };

        await _context.IPReputations.AddRangeAsync(ipProfiles);
        await _context.SaveChangesAsync();
    }

    private async Task SeedSecurityEventsAndIncidentsAsync()
    {
        if (await _context.SecurityEvents.AnyAsync()) return;

        var now = DateTime.UtcNow;

        // Baseline legitimate events
        var baselineEvents = new List<SecurityEvent>
        {
            new()
            {
                EventType = "UserLoginSuccess",
                Category = EventCategory.SuccessfulLogin,
                Severity = SeverityLevel.Low,
                SourceIp = "10.0.0.15",
                Username = "admin@securewatch.local",
                EventTimestampUtc = now.AddHours(-4),
                DeviceInfo = "Windows 11 / Chrome 132.0",
                UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/132.0",
                Description = "Successful administrator session initiated from HQ.",
                ProcessingStatus = "Processed"
            },
            new()
            {
                EventType = "UserLoginSuccess",
                Category = EventCategory.SuccessfulLogin,
                Severity = SeverityLevel.Low,
                SourceIp = "192.168.1.100",
                Username = "analyst@securewatch.local",
                EventTimestampUtc = now.AddHours(-3),
                DeviceInfo = "macOS Sonoma / Safari 17.5",
                UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                Description = "Security analyst logged into SOC dashboard.",
                ProcessingStatus = "Processed"
            }
        };

        // Attack campaign from 198.51.100.42 (Brute Force simulation)
        var maliciousEvents = new List<SecurityEvent>();
        for (int i = 0; i < 6; i++)
        {
            maliciousEvents.Add(new SecurityEvent
            {
                EventType = "UserLoginFailed",
                Category = EventCategory.FailedLogin,
                Severity = SeverityLevel.Medium,
                SourceIp = "198.51.100.42",
                Username = "admin@securewatch.local",
                EventTimestampUtc = now.AddMinutes(-25 + i * 2),
                DeviceInfo = "Linux / Python-Requests 2.31",
                UserAgent = "python-requests/2.31.0",
                Description = $"Failed login attempt #{i + 1} for target user admin@securewatch.local (Invalid Password).",
                ProcessingStatus = "Processed",
                IsSimulated = true
            });
        }

        await _context.SecurityEvents.AddRangeAsync(baselineEvents);
        await _context.SecurityEvents.AddRangeAsync(maliciousEvents);
        await _context.SaveChangesAsync();

        // Seed a ThreatDetection triggered by Rule 1
        var rule1 = await _context.SecurityRules.FirstOrDefaultAsync(r => r.Code == "RULE-01-BRUTE-FAST");
        if (rule1 != null)
        {
            var threat = new ThreatDetection
            {
                RuleId = rule1.Id,
                RuleName = rule1.Name,
                ThreatType = ThreatType.BruteForce,
                DetectionReason = "Triggered: 6 failed login attempts detected within a 12-minute window originating from malicious IP 198.51.100.42 targeting account admin@securewatch.local.",
                Severity = SeverityLevel.High,
                RiskScore = 82,
                SourceIp = "198.51.100.42",
                TargetedUsername = "admin@securewatch.local",
                DetectedAtUtc = now.AddMinutes(-15),
                EvidenceEventIdsJson = System.Text.Json.JsonSerializer.Serialize(maliciousEvents.Select(e => e.Id).ToList()),
                RecommendedActions = "1. Temporarily ban source IP 198.51.100.42 in firewall / WAF.\n2. Verify admin account MFA status.\n3. Invalidate active sessions for admin@securewatch.local if compromise suspected.",
                IncidentCreated = true,
                IsSimulated = true
            };

            await _context.ThreatDetections.AddAsync(threat);
            await _context.SaveChangesAsync();

            // Seed an active Incident
            var incident = new Incident
            {
                IncidentCode = "SEC-2026-0001",
                Title = "Active Brute-Force Authentication Spray from 198.51.100.42",
                Description = "High-volume credential brute-force campaign targeting administrative credentials. 6 consecutive failed authentications observed in telemetry.",
                Severity = SeverityLevel.High,
                RiskScore = 82,
                Status = IncidentStatus.Investigating,
                AssignedAnalystId = "analyst@securewatch.local",
                AssignedAnalystName = "Alex Rivera",
                SourceIp = "198.51.100.42",
                CreatedAtUtc = now.AddMinutes(-15),
                IsSimulated = true
            };

            await _context.Incidents.AddAsync(incident);
            await _context.SaveChangesAsync();

            // Link incident to threat detection
            threat.IncidentId = incident.Id;

            // Link events to incident
            foreach (var ev in maliciousEvents)
            {
                await _context.IncidentEvents.AddAsync(new IncidentEvent
                {
                    IncidentId = incident.Id,
                    SecurityEventId = ev.Id,
                    LinkedAtUtc = now.AddMinutes(-14)
                });
            }

            // Add note
            await _context.IncidentNotes.AddAsync(new IncidentNote
            {
                IncidentId = incident.Id,
                AuthorId = "analyst@securewatch.local",
                AuthorName = "Alex Rivera",
                NoteText = "Confirmed automated user-agent header python-requests/2.31.0. Applied temporary rate limit. Escalating to network team for perimeter ACL verification.",
                IsInternalOnly = false,
                CreatedAtUtc = now.AddMinutes(-10)
            });

            // Add alert
            await _context.Alerts.AddAsync(new Alert
            {
                IncidentId = incident.Id,
                ThreatDetectionId = threat.Id,
                Title = "High Severity Incident Raised: SEC-2026-0001",
                Message = "Brute-force attack from 198.51.100.42 exceeded threshold (Score: 82/100).",
                Severity = SeverityLevel.High,
                IsAcknowledged = true,
                AcknowledgedByName = "Alex Rivera",
                AcknowledgedAtUtc = now.AddMinutes(-8),
                CreatedAtUtc = now.AddMinutes(-15)
            });

            await _context.SaveChangesAsync();
        }
    }
}

