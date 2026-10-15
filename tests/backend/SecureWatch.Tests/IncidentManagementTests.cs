using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;
using SecureWatch.Domain.Enums;
using SecureWatch.Infrastructure.Services;
using Xunit;

namespace SecureWatch.Tests;

public class IncidentManagementTests
{
    [Fact]
    public async Task IncidentLifecycle_ShouldProgressFromOpenToInvestigatingToResolved()
    {
        // Arrange
        var context = TestDbContextFactory.CreateInMemoryDbContext(Guid.NewGuid().ToString());
        var hubMock = new Mock<ISecurityHubService>();
        var auditMock = new Mock<IAuditLogService>();
        var service = new IncidentService(context, hubMock.Object, auditMock.Object, NullLogger<IncidentService>.Instance);

        // 1. Create Incident
        var createDto = new CreateIncidentDto
        {
            Title = "Unauthorized Lateral Access Attempt",
            Description = "Anomalous internal SMB connection probe detected.",
            Severity = SeverityLevel.High,
            RiskScore = 78,
            SourceIp = "192.168.1.45"
        };

        var createResult = await service.CreateIncidentAsync(createDto);
        createResult.Success.Should().BeTrue();
        var incidentId = createResult.Data!.Id;
        createResult.Data.Status.Should().Be(IncidentStatus.Open);
        createResult.Data.IncidentCode.Should().StartWith("SEC-");

        // 2. Assign Analyst
        var assignResult = await service.AssignAnalystAsync(incidentId, "analyst.john@securewatch.local");
        assignResult.Success.Should().BeTrue();
        assignResult.Data!.Status.Should().Be(IncidentStatus.Investigating);
        assignResult.Data.AssignedAnalystId.Should().Be("analyst.john@securewatch.local");

        // 3. Add Investigation Note
        var noteResult = await service.AddNoteAsync(incidentId, new AddIncidentNoteDto
        {
            NoteText = "Confirmed port scanning tool usage. Host quarantined at switch level.",
            IsInternalOnly = false
        }, "analyst.john@securewatch.local", "John Analyst");

        noteResult.Success.Should().BeTrue();
        noteResult.Data!.NoteText.Should().Contain("quarantined");

        // 4. Resolve Incident
        var resolveResult = await service.ResolveIncidentAsync(incidentId, new ResolveIncidentDto
        {
            ResolutionSummary = "Contained compromised contractor laptop and rotated service account tickets.",
            RootCause = "Unpatched developer machine running legacy test script."
        });

        resolveResult.Success.Should().BeTrue();
        resolveResult.Data!.Status.Should().Be(IncidentStatus.Resolved);
        resolveResult.Data.ResolutionSummary.Should().Contain("Contained compromised contractor");

        // 5. Verify Full Query
        var queryResult = await service.GetIncidentByIdAsync(incidentId);
        queryResult.Success.Should().BeTrue();
        queryResult.Data!.Notes.Should().HaveCount(1);
        queryResult.Data.Status.Should().Be(IncidentStatus.Resolved);
    }
}

