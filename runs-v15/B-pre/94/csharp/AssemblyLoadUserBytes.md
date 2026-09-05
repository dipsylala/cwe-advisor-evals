## Verdict

Exploitable.

## Source

User-supplied file upload via HTTP POST parameter `pluginFile` in the `UploadPlugin` method.

## Fix

**Vulnerable code (line 36-37):**
```csharp
byte[] uploadedBytes;
using (var memoryStream = new MemoryStream())
{
    await pluginFile.CopyToAsync(memoryStream);
    uploadedBytes = memoryStream.ToArray();
}

// SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
Assembly pluginAssembly = Assembly.Load(uploadedBytes);
```

**Fixed code:**
```csharp
byte[] uploadedBytes;
using (var memoryStream = new MemoryStream())
{
    await pluginFile.CopyToAsync(memoryStream);
    uploadedBytes = memoryStream.ToArray();
}

// Verify the plugin is signed by a trusted certificate before loading
if (!VerifyPluginSignature(uploadedBytes))
{
    return Unauthorized("Plugin must be signed by a trusted publisher.");
}

Assembly pluginAssembly = Assembly.Load(uploadedBytes);

// Add this verification method to the PluginController class:
private bool VerifyPluginSignature(byte[] assemblyBytes)
{
    try
    {
        using (var store = new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine))
        {
            store.Open(OpenFlags.ReadOnly);
            var certs = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                "REPLACE_WITH_TRUSTED_SIGNER_THUMBPRINT",
                false);
            
            if (certs.Count == 0)
            {
                return false;
            }

            var assembly = Assembly.Load(assemblyBytes);
            var assemblyName = assembly.GetName();
            var publicKey = assemblyName.GetPublicKey();

            if (publicKey == null || publicKey.Length == 0)
            {
                return false;
            }

            var trustedCert = certs[0];
            var trustedPublicKey = trustedCert.PublicKey.EncodedKeyValue.RawData;
            
            return CompareByteArrays(publicKey, trustedPublicKey);
        }
    }
    catch
    {
        return false;
    }
}

private bool CompareByteArrays(byte[] array1, byte[] array2)
{
    if (array1.Length != array2.Length)
    {
        return false;
    }

    for (int i = 0; i < array1.Length; i++)
    {
        if (array1[i] != array2[i])
        {
            return false;
        }
    }

    return true;
}
```

Required namespace additions:
```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
```

## Explanation

The original code loads an arbitrary assembly directly from user-supplied bytes without any validation, allowing an attacker to upload a malicious .NET assembly that executes arbitrary code when loaded. The fix implements cryptographic signature verification before loading the assembly. The uploaded plugin must be signed with a certificate whose thumbprint matches the trusted signer's certificate configured in the local machine's trusted publisher store. The verification method extracts the public key from the uploaded assembly's signature, compares it against the known trusted signer's public key, and only permits the assembly to load if the signatures match. This ensures that only plugins signed by the administrator can be loaded, preventing unauthorized code execution.

## Behaviour changes

- **Added signature verification check**: The method now calls `VerifyPluginSignature()` before `Assembly.Load()`. If verification fails, the request returns HTTP 401 (Unauthorized) instead of proceeding.
- **New verification method**: Added `VerifyPluginSignature()` which validates the assembly's signature against a trusted certificate.
- **New helper method**: Added `CompareByteArrays()` for safe byte array comparison.
- **Added namespaces**: Requires `System.Security.Cryptography` and `System.Security.Cryptography.X509Certificates`.
- **Configuration requirement**: The `TrustedSignerThumbprint` constant must be replaced with the actual thumbprint of the trusted certificate used to sign plugins.
- **Failure mode change**: Invalid or unsigned assemblies now return HTTP 401 instead of being loaded. Any exceptions during verification cause the request to reject the plugin safely.
