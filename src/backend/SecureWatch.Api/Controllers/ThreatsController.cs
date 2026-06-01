using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Api.Controllers;

[Authorize]
public class ThreatsController : BaseApiController
{
    private readonly IThreatDetectionEngine _threatEngine;

    public ThreatsController(IThreatDetectionEngine threatEngine)
    {
        _threatEngine = threatEngine;
    }

    [HttpGet]
    public async Task<IActionResult> GetThreats([FromQuery] ThreatQueryParameters parameters, CancellationToken ct)
    {
        var result = await _threatEngine.GetThreatsAsync(parameters, ct);
        return HandleResult(result);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetThreatById(Guid id, CancellationToken ct)
    {
        var result = await _threatEngine.GetThreatByIdAsync(id, ct);
        return HandleResult(result);
    }

    [HttpGet("statistics")]
    public async Task<IActionResult> GetStatistics(CancellationToken ct)
    {
        var result = await _threatEngine.GetThreatStatisticsAsync(ct);
        return HandleResult(result);
    }
}

