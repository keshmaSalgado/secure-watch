using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Infrastructure.Services;

public class SecurityHub : Hub
{
    public async Task JoinMonitoringGroup()
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, "SecurityMonitoring");
    }

    public async Task LeaveMonitoringGroup()
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, "SecurityMonitoring");
    }
}

public class SecurityHubService : ISecurityHubService
{
    private readonly IHubContext<SecurityHub> _hubContext;

    public SecurityHubService(IHubContext<SecurityHub> hubContext)
    {
        _hubContext = hubContext;
    }

    public async Task BroadcastSecurityEventAsync(SecurityEventDto securityEvent)
    {
        await _hubContext.Clients.All.SendAsync("ReceiveSecurityEvent", securityEvent);
    }

    public async Task BroadcastThreatDetectionAsync(ThreatDetectionDto threat)
    {
        await _hubContext.Clients.All.SendAsync("ReceiveThreatDetection", threat);
    }

    public async Task BroadcastIncidentCreatedAsync(IncidentDto incident)
    {
        await _hubContext.Clients.All.SendAsync("ReceiveIncidentCreated", incident);
    }

    public async Task BroadcastIncidentUpdatedAsync(IncidentDto incident)
    {
        await _hubContext.Clients.All.SendAsync("ReceiveIncidentUpdated", incident);
    }

    public async Task BroadcastAlertAsync(string title, string message, string severity)
    {
        await _hubContext.Clients.All.SendAsync("ReceiveAlert", new { title, message, severity, timestamp = DateTime.UtcNow });
    }
}

