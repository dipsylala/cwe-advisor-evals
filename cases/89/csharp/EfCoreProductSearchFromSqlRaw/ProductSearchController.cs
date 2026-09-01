using Microsoft.AspNetCore.Mvc;

namespace Cases.SqlInjection;

[ApiController]
[Route("api/products")]
public sealed class ProductSearchController : ControllerBase
{
    private readonly ProductSearchRepository _repository;

    public ProductSearchController(ProductSearchRepository repository)
    {
        _repository = repository;
    }

    [HttpGet("search")]
    public async System.Threading.Tasks.Task<IActionResult> Search([FromQuery] string q)
    {
        var tenantId = User.FindFirst("tenant_id")?.Value ?? "";
        var products = await _repository.SearchAsync(tenantId, q ?? "");
        return Ok(products);
    }
}
