using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Api.Controllers;

[Authorize]
public class SimulatorController : BaseApiController
{
    private readonly IEventSimulatorService _simulatorService;

    public SimulatorController(IEventSimulatorService simulatorService)
    {
        _simulatorService = simulatorService;
    }

    [HttpPost("trigger-scenario")]
    public async Task<IActionResult> TriggerScenario([FromQuery] string scenarioType, CancellationToken ct)
    {
        var result = await _simulatorService.TriggerScenarioAsync(scenarioType, ct);
        return HandleResult(result);
    }

    [HttpPost("reset-demo-data")]
    public async Task<IActionResult> ResetDemoData(CancellationToken ct)
    {
        var result = await _simulatorService.ResetDemoDataAsync(ct);
        return HandleResult(result);
    }
}

