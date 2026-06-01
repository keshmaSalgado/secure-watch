using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Api.Controllers;

[Authorize]
public class DashboardController : BaseApiController
{
    private readonly IDashboardService _dashboardService;

    public DashboardController(IDashboardService dashboardService)
    {
        _dashboardService = dashboardService;
    }

    [HttpGet("overview")]
    public async Task<IActionResult> GetOverview(CancellationToken ct)
    {
        var result = await _dashboardService.GetOverviewAsync(ct);
        return HandleResult(result);
    }

    [HttpGet("threat-trends")]
    public async Task<IActionResult> GetThreatTrends([FromQuery] int hours = 24, CancellationToken ct = default)
    {
        var result = await _dashboardService.GetThreatTrendsAsync(hours, ct);
        return HandleResult(result);
    }

    [HttpGet("risk-distribution")]
    public async Task<IActionResult> GetRiskDistribution(CancellationToken ct)
    {
        var result = await _dashboardService.GetRiskDistributionAsync(ct);
        return HandleResult(result);
    }
}

