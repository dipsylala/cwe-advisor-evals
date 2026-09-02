namespace DocumentPortal.Services;

public record DocumentUpload(string FileName, string ContentType, byte[] Content);

public record DocumentRecord(int Id, string FileName, string OwnerUserId);

public interface IDocumentService
{
    Task<DocumentRecord?> GetAsync(int id);
    Task<DocumentRecord> CreateAsync(DocumentUpload upload);
    Task<bool> DeleteAsync(int id);
}

public class DocumentService : IDocumentService
{
    private readonly Dictionary<int, DocumentRecord> _documents = new();

    public Task<DocumentRecord?> GetAsync(int id)
    {
        _documents.TryGetValue(id, out var document);
        return Task.FromResult(document);
    }

    public Task<DocumentRecord> CreateAsync(DocumentUpload upload)
    {
        var id = _documents.Count + 1;
        var record = new DocumentRecord(id, upload.FileName, OwnerUserId: "system");
        _documents[id] = record;
        return Task.FromResult(record);
    }

    public Task<bool> DeleteAsync(int id)
    {
        return Task.FromResult(_documents.Remove(id));
    }
}
