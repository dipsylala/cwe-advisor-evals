using Microsoft.AspNetCore.Mvc;

namespace Cases.SqlInjection;

[ApiController]
[Route("api/metrics")]
public sealed class MetricsController : ControllerBase
{
    private readonly AuditMetricRepository _repository;

    public MetricsController(AuditMetricRepository repository)
    {
        _repository = repository;
    }

    [HttpGet("actor-count")]
    public IActionResult ActorCount([FromQuery] string actor)
    {
        var count = _repository.CountEvents(actor ?? "");
        return Ok(new { count });
    }
}
