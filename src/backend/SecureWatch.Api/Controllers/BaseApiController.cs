using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using SecureWatch.Application.Common;

namespace SecureWatch.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public abstract class BaseApiController : ControllerBase
{
    protected string CurrentUserId => User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub") ?? string.Empty;
    protected string CurrentUsername => User.Identity?.Name ?? "Anonymous";
    protected string ClientIpAddress => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

    protected IActionResult HandleResult<T>(ApiResponse<T> result)
    {
        if (result.Success)
        {
            return Ok(result);
        }

        return BadRequest(result);
    }
}

