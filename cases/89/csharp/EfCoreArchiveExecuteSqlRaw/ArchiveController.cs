using Microsoft.AspNetCore.Mvc;

namespace Cases.SqlInjection;

[ApiController]
[Route("api/archive")]
public sealed class ArchiveController : ControllerBase
{
    private readonly ArchiveService _service;

    public ArchiveController(ArchiveService service)
    {
        _service = service;
    }

    [HttpPost("orders")]
    public async System.Threading.Tasks.Task<IActionResult> Archive([FromBody] ArchiveRequest request)
    {
        var archived = await _service.ArchiveAsync(request.AccountId, request.Status, request.BeforeUtc);
        return Ok(new { archived });
    }
}

public sealed record ArchiveRequest(string AccountId, string Status, System.DateTime BeforeUtc);
