using Microsoft.AspNetCore.Mvc;

namespace Cases.SqlInjection;

[ApiController]
[Route("admin/cleanup")]
public sealed class AdminCleanupController : ControllerBase
{
    private readonly CleanupRepository _repository;

    public AdminCleanupController(CleanupRepository repository)
    {
        _repository = repository;
    }

    [HttpDelete("tenant/{tenantId}/logs")]
    public IActionResult DeleteLogs(string tenantId, [FromQuery] string before)
    {
        var deleted = _repository.DeleteLogs(tenantId, before);
        return Ok(new { deleted });
    }
}
