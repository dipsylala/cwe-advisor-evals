using DocumentPortal.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DocumentPortal;

// Existing MVC controller. Every action here correctly carries [Authorize],
// so this file is not the finding - it is included for contrast with the
// Minimal API route registered separately in Program.cs.
[Authorize]
[ApiController]
[Route("api/documents")]
public class DocumentsController : ControllerBase
{
    private readonly IDocumentService _documentService;

    public DocumentsController(IDocumentService documentService)
    {
        _documentService = documentService;
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetDocument(int id)
    {
        var document = await _documentService.GetAsync(id);
        if (document is null)
        {
            return NotFound();
        }

        return Ok(document);
    }

    [HttpPost]
    public async Task<IActionResult> UploadDocument([FromBody] DocumentUpload upload)
    {
        var created = await _documentService.CreateAsync(upload);
        return CreatedAtAction(nameof(GetDocument), new { id = created.Id }, created);
    }
}
