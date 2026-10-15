using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Entities;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Persistence;
using SecureWatch.Infrastructure.Services;
using Xunit;

namespace SecureWatch.Tests;

public class ThreatDetectionTests
{
    private static async Task SeedRulesAsync(SecureWatchDbContext context)
    {
        if (await context.SecurityRules.AnyAsync()) return;

        context.SecurityRules.AddRange(
            new SecurityRule
            {
                Name = "5 Failed Logins within 1 Minute",
                Code = "RULE-01-BRUTE-FAST",
                Category = EventCategory.FailedLogin,
                ThreatType = ThreatType.BruteForce,
                Severity = SeverityLevel.High,
                TimeWindowSeconds = 60,
                ThresholdCount = 5,
                BaseRiskScore = 75,
                IsEnabled = true
            },
            new SecurityRule
            {
                Name = "20 Failed Logins within 2 Minutes",
                Code = "RULE-02-BRUTE-AGGRESSIVE",
                Category = EventCategory.FailedLogin,
                ThreatType = ThreatType.RapidFailures,
                Severity = SeverityLevel.Critical,
                TimeWindowSeconds = 120,
                ThresholdCount = 20,
                BaseRiskScore = 90,
                IsEnabled = true
            },
            new SecurityRule
            {
                Name = "Multiple Accounts Accessed from Single IP",
                Code = "RULE-04-MULTI-ACCOUNT-SPRAY",
                Category = EventCategory.FailedLogin,
                ThreatType = ThreatType.MultiAccountTargeting,
                Severity = SeverityLevel.High,
                TimeWindowSeconds = 300,
                ThresholdCount = 3,
                BaseRiskScore = 85,
                IsEnabled = true
            },
            new SecurityRule
            {
                Name = "Login from Known Malicious IP",
                Code = "RULE-05-MALICIOUS-IP",
                Category = EventCategory.FailedLogin,
                ThreatType = ThreatType.MaliciousIpActivity,
                Severity = SeverityLevel.Critical,
                TimeWindowSeconds = 60,
                ThresholdCount = 1,
                BaseRiskScore = 95,
                IsEnabled = true
            }
        );

        await context.SaveChangesAsync();
    }

    [Fact]
    public async Task EvaluateEvent_ShouldTriggerRule01_WhenFiveFailedLoginsOccurWithinOneMinute()
    {
        // Arrange
        var context = TestDbContextFactory.CreateInMemoryDbContext(Guid.NewGuid().ToString());
        await SeedRulesAsync(context);

        var ipMock = new Mock<IIpReputationService>();
        ipMock.Setup(x => x.GetReputationAsync(It.IsAny<string>(), default))
              .ReturnsAsync(Application.Common.ApiResponse<IpReputationDto>.Ok(new IpReputationDto { ReputationScore = 20 }));

        var hubMock = new Mock<ISecurityHubService>();
        var engine = new ThreatDetectionEngine(context, ipMock.Object, hubMock.Object, NullLogger<ThreatDetectionEngine>.Instance);

        var testIp = "192.0.2.10";
        var now = DateTime.UtcNow;

        // Ingest 4 prior failed logins in context
        for (int i = 0; i < 4; i++)
        {
            context.SecurityEvents.Add(new SecurityEvent
            {
                EventType = "UserLoginFailed",
                Category = EventCategory.FailedLogin,
                Severity = SeverityLevel.Medium,
                SourceIp = testIp,
                Username = "test.target@securewatch.local",
                EventTimestampUtc = now.AddSeconds(-10 * (4 - i)),
                Description = "Failed password"
            });
        }
        await context.SaveChangesAsync();

        // Act: 5th failed login
        var currentEvent = new SecurityEvent
        {
            EventType = "UserLoginFailed",
            Category = EventCategory.FailedLogin,
            Severity = SeverityLevel.Medium,
            SourceIp = testIp,
            Username = "test.target@securewatch.local",
            EventTimestampUtc = now,
            Description = "Failed password"
        };
        context.SecurityEvents.Add(currentEvent);
        await context.SaveChangesAsync();

        var detections = await engine.EvaluateEventAsync(currentEvent);

        // Assert
        detections.Should().NotBeEmpty();
        var bruteForce = detections.FirstOrDefault(d => d.ThreatType == ThreatType.BruteForce);
        bruteForce.Should().NotBeNull();
        bruteForce!.RiskScore.Should().BeGreaterThanOrEqualTo(75);
        bruteForce.Severity.Should().Be(SeverityLevel.High);
        bruteForce.SourceIp.Should().Be(testIp);

        // Automatic incident created
        var incident = await context.Incidents.FirstOrDefaultAsync(i => i.SourceIp == testIp);
        incident.Should().NotBeNull();
        incident!.Status.Should().Be(IncidentStatus.Open);
    }

    [Fact]
    public async Task EvaluateEvent_ShouldTriggerRule05_WhenSourceIpIsKnownMalicious()
    {
        // Arrange
        var context = TestDbContextFactory.CreateInMemoryDbContext(Guid.NewGuid().ToString());
        await SeedRulesAsync(context);

        var hostileIp = "198.51.100.99";
        var ipMock = new Mock<IIpReputationService>();
        ipMock.Setup(x => x.GetReputationAsync(hostileIp, default))
              .ReturnsAsync(Application.Common.ApiResponse<IpReputationDto>.Ok(new IpReputationDto
              {
                  IpAddress = hostileIp,
                  IsMalicious = true,
                  ReputationScore = 95,
                  Isp = "Hostile Botnet AS",
                  CountryName = "Malicious Nation"
              }));

        var hubMock = new Mock<ISecurityHubService>();
        var engine = new ThreatDetectionEngine(context, ipMock.Object, hubMock.Object, NullLogger<ThreatDetectionEngine>.Instance);

        var currentEvent = new SecurityEvent
        {
            EventType = "UserLoginFailed",
            Category = EventCategory.FailedLogin,
            Severity = SeverityLevel.High,
            SourceIp = hostileIp,
            Username = "finance@securewatch.local",
            EventTimestampUtc = DateTime.UtcNow,
            Description = "Hostile probe"
        };
        context.SecurityEvents.Add(currentEvent);
        await context.SaveChangesAsync();

        // Act
        var detections = await engine.EvaluateEventAsync(currentEvent);

        // Assert
        var hostileDetection = detections.FirstOrDefault(d => d.ThreatType == ThreatType.MaliciousIpActivity);
        hostileDetection.Should().NotBeNull();
        hostileDetection!.RiskScore.Should().Be(95);
        hostileDetection.Severity.Should().Be(SeverityLevel.Critical);
    }

    [Fact]
    public async Task EvaluateEvent_ShouldTriggerRule04_WhenMultipleAccountsTargetedFromSingleIp()
    {
        // Arrange
        var context = TestDbContextFactory.CreateInMemoryDbContext(Guid.NewGuid().ToString());
        await SeedRulesAsync(context);

        var ipMock = new Mock<IIpReputationService>();
        ipMock.Setup(x => x.GetReputationAsync(It.IsAny<string>(), default))
              .ReturnsAsync(Application.Common.ApiResponse<IpReputationDto>.Ok(new IpReputationDto { ReputationScore = 10 }));

        var hubMock = new Mock<ISecurityHubService>();
        var engine = new ThreatDetectionEngine(context, ipMock.Object, hubMock.Object, NullLogger<ThreatDetectionEngine>.Instance);

        var attackerIp = "203.0.113.55";
        var now = DateTime.UtcNow;

        context.SecurityEvents.AddRange(
            new SecurityEvent { SourceIp = attackerIp, Username = "user1@securewatch.local", Category = EventCategory.FailedLogin, EventTimestampUtc = now.AddSeconds(-30) },
            new SecurityEvent { SourceIp = attackerIp, Username = "user2@securewatch.local", Category = EventCategory.FailedLogin, EventTimestampUtc = now.AddSeconds(-20) }
        );
        await context.SaveChangesAsync();

        // 3rd user targeted
        var currentEvent = new SecurityEvent
        {
            SourceIp = attackerIp,
            Username = "user3@securewatch.local",
            Category = EventCategory.FailedLogin,
            EventTimestampUtc = now
        };
        context.SecurityEvents.Add(currentEvent);
        await context.SaveChangesAsync();

        // Act
        var detections = await engine.EvaluateEventAsync(currentEvent);

        // Assert
        var spray = detections.FirstOrDefault(d => d.ThreatType == ThreatType.MultiAccountTargeting);
        spray.Should().NotBeNull();
        spray!.Severity.Should().Be(SeverityLevel.High);
        spray.RiskScore.Should().Be(85);
    }
}
