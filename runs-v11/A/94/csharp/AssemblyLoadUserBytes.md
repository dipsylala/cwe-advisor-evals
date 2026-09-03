## Verdict

CWE-94: Code Injection via unsanitized assembly loading. The application accepts arbitrary file upload bytes and loads them directly as a .NET assembly without validation, allowing an attacker to execute arbitrary code with the application's privileges.

## Source

Line 37 in `PluginController.cs`:
```
Assembly pluginAssembly = Assembly.Load(uploadedBytes);
```

The vulnerability is that `Assembly.Load(byte[])` accepts untrusted user input (bytes from an uploaded file) and directly instantiates executable code within the current process without:
- Verifying the assembly's identity or source
- Validating its content or structure
- Restricting its permissions or capabilities

An attacker can upload a malicious compiled assembly that executes arbitrary code when loaded.

## Fix

Implement cryptographic signature verification before assembly loading:

1. Obtain the uploaded file bytes as is done currently (lines 29-34).

2. Verify the assembly's strong name or Authenticode signature before loading. Use `System.Reflection.Metadata` to read assembly headers and validate the signature against a known public key or certificate:

```csharp
// Verify signature of the uploaded assembly bytes before loading
if (!VerifyAssemblySignature(uploadedBytes, trustedPublicKeyToken))
{
    return BadRequest("Plugin assembly signature verification failed.");
}

Assembly pluginAssembly = Assembly.Load(uploadedBytes);
```

3. Implement the verification method to check that:
   - The assembly carries a strong name with a matching public key token
   - OR the assembly is signed with an Authenticode certificate whose thumbprint is in a whitelist of trusted publishers

4. Additional hardening:
   - Validate the assembly's `AssemblyName` to ensure it is an expected plugin assembly name and version.
   - Restrict execution scope by loading into a separate `AssemblyLoadContext` with minimal permissions if feasible.
   - Log all plugin load attempts (successful and failed) for audit purposes.
   - Require administrative authentication before allowing plugin uploads (already implied by the design, but enforce in the action).

## Explanation

CWE-94 in this context arises because the application treats user-supplied bytes as trusted code. The fix centers on establishing trust: only load assemblies you can cryptographically verify came from a known, authorized source (your own build process, a trusted publisher, or an administrator holding a private key).

Strong naming is the standard C# defense: compile plugin assemblies with a private key held by your organization, and verify the public key token matches before loading. This ensures that only code you or a trusted publisher built can be loaded.

Authenticode signing (via certificates) is an alternative when strong naming isn't available, using the same principle: whitelist the certificate thumbprints of publishers you trust, then verify each uploaded assembly against that list.

Without signature verification, the upload endpoint is equivalent to arbitrary code execution on the server.
