namespace Cases.Authorization;

public sealed record InvoiceExport(byte[] PdfBytes, string FileName, string AccountId);

public sealed class InvoiceRepository
{
    public System.Threading.Tasks.Task<InvoiceExport?> LoadForExportAsync(string invoiceId)
    {
        return System.Threading.Tasks.Task.FromResult<InvoiceExport?>(new InvoiceExport(System.Array.Empty<byte>(), invoiceId + ".pdf", "acct-42"));
    }
}
