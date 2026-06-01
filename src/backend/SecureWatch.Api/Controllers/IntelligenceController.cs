using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Api.Controllers;

[Authorize]
public class IntelligenceController : BaseApiController
{
    private readonly IIpReputationService _ipReputationService;

    public IntelligenceController(IIpReputationService ipReputationService)
    {
        _ipReputationService = ipReputationService;
    }

    [HttpGet("ip/{address}")]
    public async Task<IActionResult> GetIpReputation(string address, CancellationToken ct)
    {
        var result = await _ipReputationService.GetReputationAsync(address, ct);
        return HandleResult(result);
    }

    [HttpPost("ip/{address}/refresh")]
    public async Task<IActionResult> ForceRefreshIp(string address, CancellationToken ct)
    {
        var result = await _ipReputationService.ForceRefreshAsync(address, ct);
        return HandleResult(result);
    }
}

