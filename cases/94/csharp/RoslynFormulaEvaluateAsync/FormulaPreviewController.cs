using Microsoft.AspNetCore.Mvc;

namespace Cases.CodeInjection;

[ApiController]
[Route("api/formulas")]
public sealed class FormulaPreviewController : ControllerBase
{
    private readonly FormulaEvaluator _evaluator;

    public FormulaPreviewController(FormulaEvaluator evaluator)
    {
        _evaluator = evaluator;
    }

    [HttpPost("preview")]
    public async System.Threading.Tasks.Task<IActionResult> Preview([FromBody] FormulaPreviewRequest request)
    {
        var value = await _evaluator.EvaluateAsync(request.Expression, new InvoiceSample(100, 8));
        return Ok(new { value });
    }
}

public sealed record FormulaPreviewRequest(string Expression);
public sealed record InvoiceSample(decimal Total, decimal Tax);
