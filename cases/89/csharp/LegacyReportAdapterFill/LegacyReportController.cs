using Microsoft.AspNetCore.Mvc;

namespace Cases.SqlInjection;

[ApiController]
[Route("legacy/reports")]
public sealed class LegacyReportController : ControllerBase
{
    private readonly LegacyReportRepository _repository;

    public LegacyReportController(LegacyReportRepository repository)
    {
        _repository = repository;
    }

    [HttpGet("customers")]
    public IActionResult Customers([FromQuery] string region)
    {
        var table = _repository.LoadCustomers(region ?? "");
        return Ok(table);
    }
}
