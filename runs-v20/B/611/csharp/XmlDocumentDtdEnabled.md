## Verdict

Confirmed. `XmlDocument.LoadXml(xmlPayload)` at line 14 parses a request-body string directly, and `XmlDocument` carries no null default for `XmlResolver` when loaded outside an `XmlReader` (its own resolver is always used, per Microsoft's documentation). An attacker-supplied `<!DOCTYPE>` with a `SYSTEM`/`PUBLIC` external entity is resolved and expanded, then read back via `SelectSingleNode("//name")` and returned in the HTTP response - a classic XXE file-disclosure / SSRF path.

## Source

`xmlPayload`, the `[FromBody] string` parameter of `ImportController.Upload`, bound directly from the untrusted HTTP request body.

## Fix

Data flow: `xmlPayload` (untrusted, HTTP request body) -> `doc.LoadXml(xmlPayload)` (sink, line 14) -> `doc.SelectSingleNode("//name")` -> returned in the HTTP response. No validation or encoding occurs between source and sink.

Sink contract for the original `doc.LoadXml(string)` call:
- **Returns:** void; populates `doc`'s DOM in place from the parsed string.
- **Discards:** nothing beyond the parsed nodes themselves.
- **Arguments left implicit:** `doc.XmlResolver` is never set, so `XmlDocument` uses its built-in default resolver (an `XmlUrlResolver`), which resolves external DTDs/entities from the filesystem or network. DTD processing itself has no on/off switch on `XmlDocument` - unlike `XmlReaderSettings.DtdProcessing`, there is no property to reject `<!DOCTYPE>` outright at this API.
- **Failure behaviour:** throws `XmlException` on malformed XML; this is unchanged by the fix for well-formed non-DTD input.

Per `cwe/611/csharp/INDEX.md`, `XmlDocument` is the one API where the runtime defaults do not protect the caller, and the prescribed remediation is to route the load through an `XmlReader` configured with `DtdProcessing = DtdProcessing.Prohibit` and `XmlResolver = null` (the strongest option - rejecting `<!DOCTYPE>` entirely), and additionally set `doc.XmlResolver = null` directly, since a resolver configured on the reader is not retained by the document after `Load` returns.

No third-party library is involved; this is a BCL (`System.Xml`) configuration fix.

### File: XmlDocumentDtdEnabled.cs

```csharp
using System.IO;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ImportController : ControllerBase
{
    [HttpPost("upload")]
    public IActionResult Upload([FromBody] string xmlPayload)
    {
        var doc = new XmlDocument();
        doc.XmlResolver = null;

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };

        using (var stringReader = new StringReader(xmlPayload))
        using (var xmlReader = XmlReader.Create(stringReader, settings))
        {
            doc.Load(xmlReader);
        }

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

## Explanation

The vulnerable line loaded untrusted XML with `XmlDocument.LoadXml(string)`, an API whose resolver defaults to an active `XmlUrlResolver` and which has no direct way to prohibit DTDs. The fix wraps the same string in an `XmlReader` built from `XmlReaderSettings` with `DtdProcessing = DtdProcessing.Prohibit` (rejects any `<!DOCTYPE>` outright, closing both external-entity disclosure and internal-entity-expansion DoS) and `XmlResolver = null` (belt-and-braces against external resolution), then loads the document via `doc.Load(xmlReader)` instead of `doc.LoadXml(xmlPayload)`. `doc.XmlResolver` is also explicitly set to `null` on the document itself, because a resolver configured only on the reader is not retained by the `XmlDocument` once `Load` returns, and Microsoft's own documentation notes `XmlDocument` always falls back to its own resolver outside of the initial reader-driven parse. For any XML payload without a DOCTYPE, parsing and the resulting DOM (`SelectSingleNode("//name")`) are identical to before; a payload carrying a DOCTYPE now fails fast instead of being resolved and expanded.

Checked with `dotnet build` against a scratch ASP.NET Core (net8.0) Web SDK project containing this exact controller file: build succeeded, 0 warnings, 0 errors. Every symbol the fix introduces beyond the original file - `StringReader` (`System.IO`), `XmlReaderSettings`, `DtdProcessing.Prohibit`, `XmlReader.Create(TextReader, XmlReaderSettings)`, `XmlDocument.Load(XmlReader)`, and `XmlDocument.XmlResolver` - is a standard `System.Xml`/`System.IO` BCL member, all named directly in the loaded C# guidance except `StringReader`, which is the standard way to adapt an in-memory `string` to the `TextReader` overload of `XmlReader.Create`.

## Behaviour changes

- Any request body containing a `<!DOCTYPE>` declaration (legitimate internal-subset use included) now causes `doc.Load(xmlReader)` to throw an `XmlException` instead of being parsed - this is the intended effect of prohibiting DTDs and will surface as an unhandled-exception/500 response unless the controller already has broader exception handling. No test in the shown code path exercises DOCTYPE-bearing input, so no currently-passing behaviour relies on DTDs being accepted.
- For all other well-formed XML input (the case with no DOCTYPE), parsing result, `SelectSingleNode("//name")` output, and the HTTP response are unchanged.
