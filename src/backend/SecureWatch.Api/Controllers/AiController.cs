using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Api.Controllers;

[Authorize]
public class AiController : BaseApiController
{
    private readonly IAiAssistantService _aiService;

    public AiController(IAiAssistantService aiService)
    {
        _aiService = aiService;
    }

    [HttpPost("analyze-incident")]
    public async Task<IActionResult> AnalyzeIncident([FromBody] AiIncidentAnalysisRequestDto request, CancellationToken ct)
    {
        var result = await _aiService.AnalyzeIncidentAsync(request, ct);
        return HandleResult(result);
    }

    [HttpPost("generate-report")]
    public async Task<IActionResult> GenerateReport([FromBody] AiReportRequestDto request, CancellationToken ct)
    {
        var result = await _aiService.GenerateReportAsync(request, ct);
        return HandleResult(result);
    }

    [HttpPost("chat")]
    public async Task<IActionResult> Chat([FromBody] AiChatRequestDto request, CancellationToken ct)
    {
        var result = await _aiService.ChatAsync(request, ct);
        return HandleResult(result);
    }

    [HttpPost("anomaly-detection")]
    public async Task<IActionResult> DetectAnomalies(CancellationToken ct)
    {
        var result = await _aiService.DetectAnomaliesAsync(ct);
        return HandleResult(result);
    }
}

