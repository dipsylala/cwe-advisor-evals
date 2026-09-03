## Verdict

Exploitable

## Source

HTTP file upload parameter `pluginFile` received at line 22 in `UploadPlugin()` method.

## Fix

**Vulnerable Code (line 37):**
```csharp
Assembly pluginAssembly = Assembly.Load(uploadedBytes);
```

**Fixed Code:**
```csharp
// Replace dynamic assembly loading with a safe plugin architecture.
// Approved plugins are pre-deployed or validated against a cryptographic hash allowlist.
// Example: use a configuration file listing approved plugin paths and their SHA256 hashes.

var approvedPlugins = configuration.GetSection("ApprovedPlugins").Get<Dictionary<string, string>>();

using (var sha256 = System.Security.Cryptography.SHA256.Create())
{
    byte[] hash = sha256.ComputeHash(uploadedBytes);
    string uploadedHash = Convert.ToHexString(hash);
    
    bool isApproved = approvedPlugins.Values.Contains(uploadedHash);
    if (!isApproved)
    {
        return BadRequest("Plugin not in approved list. Contact an administrator to register this plugin.");
    }
}

// Load from a validated, pre-deployed path instead of from upload bytes
string approvedPluginPath = approvedPlugins.Keys.FirstOrDefault(key => approvedPlugins[key] == uploadedHash);
if (approvedPluginPath == null)
{
    return BadRequest("Plugin hash mismatch.");
}

Assembly pluginAssembly = Assembly.LoadFrom(approvedPluginPath);
```

## Explanation

The original code passes untrusted bytes directly to `Assembly.Load()`, which executes arbitrary managed code with full application privileges. This allows an attacker to upload a malicious assembly that performs any operation the host application can perform, including database access, credential theft, or lateral movement. The fix replaces dynamic loading from user input with a cryptographic hash-based allowlist that is controlled by the server. Only administrators can add plugins to the approved list; the code computes a SHA256 hash of the uploaded file and checks it against known-good values. If the hash matches, the code loads the pre-deployed assembly from a secure path rather than the untrusted upload bytes. This ensures that only vetted plugins can execute, even if an attacker uploads a file claiming to be an approved plugin.

## Behaviour changes

- **Approval check added**: The method now validates the uploaded assembly against a server-controlled allowlist before loading. Unapproved assemblies are rejected with HTTP 400.
- **Hash comparison**: A SHA256 hash of the uploaded bytes is computed and compared to hashes stored in configuration. This prevents an attacker from bypassing the allowlist by crafting new assemblies.
- **Filesystem load instead of in-memory load**: `Assembly.LoadFrom(approvedPluginPath)` loads from a pre-deployed, audited path instead of `Assembly.Load(uploadedBytes)`. This ensures only pre-approved binaries execute.
- **Added dependency on configuration**: The code now requires an `ApprovedPlugins` section in application configuration mapping plugin names to their expected SHA256 hashes. Administrators must register each plugin's hash before it can be used.
- **New failure cases**: Requests with hashes not in the allowlist or mismatched paths now return 400 Bad Request instead of attempting to load the assembly. This is a **security-necessary** behaviour change that rejects unauthorized plugin installations at upload time rather than executing untrusted code.
