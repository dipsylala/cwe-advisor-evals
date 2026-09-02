using DocumentPortal.Services;

namespace DocumentPortal;

public static class DocumentEndpoints
{
    public static async Task<IResult> DeleteDocument(int id, IDocumentService documentService)
    {
        var deleted = await documentService.DeleteAsync(id);
        if (!deleted)
        {
            return Results.NotFound();
        }

        return Results.NoContent();
    }
}
