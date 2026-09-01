using Microsoft.AspNetCore.Mvc;

namespace Cases.SqlInjection;

[ApiController]
[Route("api/customers")]
public sealed class CustomerSearchController : ControllerBase
{
    private readonly CustomerSearchService _service;

    public CustomerSearchController(CustomerSearchService service)
    {
        _service = service;
    }

    [HttpGet]
    public async System.Threading.Tasks.Task<IActionResult> Search([FromQuery] string? q, [FromQuery] string? sort)
    {
        var accountId = User.FindFirst("account_id")?.Value ?? "";
        var rows = await _service.SearchAsync(accountId, new CustomerSearchOptions(q ?? "", sort ?? "created_at"));
        return Ok(rows);
    }
}
