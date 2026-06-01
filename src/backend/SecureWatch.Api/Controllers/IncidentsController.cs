using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.DTOs;
using SecureWatch.Application.Interfaces;

namespace SecureWatch.Api.Controllers;

[Authorize]
public class IncidentsController : BaseApiController
{
    private readonly IIncidentService _incidentService;

    public IncidentsController(IIncidentService incidentService)
    {
        _incidentService = incidentService;
    }

    [HttpGet]
    public async Task<IActionResult> GetIncidents([FromQuery] IncidentQueryParameters parameters, CancellationToken ct)
    {
        var result = await _incidentService.GetIncidentsAsync(parameters, ct);
        return HandleResult(result);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetIncidentById(Guid id, CancellationToken ct)
    {
        var result = await _incidentService.GetIncidentByIdAsync(id, ct);
        return HandleResult(result);
    }

    [HttpPost]
    public async Task<IActionResult> CreateIncident([FromBody] CreateIncidentDto request, CancellationToken ct)
    {
        var result = await _incidentService.CreateIncidentAsync(request, ct);
        return HandleResult(result);
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> UpdateIncident(Guid id, [FromBody] UpdateIncidentDto request, CancellationToken ct)
    {
        var result = await _incidentService.UpdateIncidentAsync(id, request, ct);
        return HandleResult(result);
    }

    [HttpPost("{id:guid}/assign")]
    public async Task<IActionResult> AssignAnalyst(Guid id, [FromBody] string analystId, CancellationToken ct)
    {
        var result = await _incidentService.AssignAnalystAsync(id, analystId, ct);
        return HandleResult(result);
    }

    [HttpPost("{id:guid}/notes")]
    public async Task<IActionResult> AddNote(Guid id, [FromBody] AddIncidentNoteDto request, CancellationToken ct)
    {
        var result = await _incidentService.AddNoteAsync(id, request, CurrentUserId, CurrentUsername, ct);
        return HandleResult(result);
    }

    [HttpPost("{id:guid}/resolve")]
    public async Task<IActionResult> ResolveIncident(Guid id, [FromBody] ResolveIncidentDto request, CancellationToken ct)
    {
        var result = await _incidentService.ResolveIncidentAsync(id, request, ct);
        return HandleResult(result);
    }
}

