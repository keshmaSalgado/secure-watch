using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Api.Controllers;

[Authorize]
public class EventsController : BaseApiController
{
    private readonly ISecurityEventService _eventService;

    public EventsController(ISecurityEventService eventService)
    {
        _eventService = eventService;
    }

    [HttpPost]
    public async Task<IActionResult> IngestEvent([FromBody] CreateSecurityEventDto request, CancellationToken ct)
    {
        var result = await _eventService.IngestEventAsync(request, ct);
        return HandleResult(result);
    }

    [HttpPost("batch")]
    public async Task<IActionResult> IngestBatch([FromBody] List<CreateSecurityEventDto> requests, CancellationToken ct)
    {
        var result = await _eventService.IngestBatchAsync(requests, ct);
        return HandleResult(result);
    }

    [HttpGet]
    public async Task<IActionResult> GetEvents([FromQuery] EventQueryParameters parameters, CancellationToken ct)
    {
        var result = await _eventService.GetEventsAsync(parameters, ct);
        return HandleResult(result);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetEventById(Guid id, CancellationToken ct)
    {
        var result = await _eventService.GetEventByIdAsync(id, ct);
        return HandleResult(result);
    }

    [HttpGet("statistics")]
    public async Task<IActionResult> GetStatistics(CancellationToken ct)
    {
        var result = await _eventService.GetStatisticsAsync(ct);
        return HandleResult(result);
    }
}

