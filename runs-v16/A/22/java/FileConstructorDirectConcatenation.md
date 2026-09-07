## Verdict

Path traversal vulnerability confirmed. The `fileName` parameter from the HTTP request is used directly to construct a file path without validation, allowing an attacker to escape the document store directory using sequences like `../`.

## Source

Line 39 constructs the file path by concatenating an unsanitized user-supplied parameter:

```java
File requestedFile = new File(DOCUMENT_STORE_DIR + File.separator + fileName);
```

The `fileName` parameter (line 32) comes directly from the request without validation or normalization.

## Fix

Resolve both the base directory and requested file to their canonical paths, then verify that the requested file is contained within the base directory before accessing it:

```java
File baseDir = new File(DOCUMENT_STORE_DIR).getCanonicalFile();
File requestedFile = new File(baseDir, fileName).getCanonicalFile();

// Verify the resolved file is within the base directory
if (!requestedFile.getAbsolutePath().startsWith(baseDir.getAbsolutePath() + File.separator) && 
    !requestedFile.equals(baseDir)) {
    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
    return;
}

if (!requestedFile.exists()) {
    response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
    return;
}
```

The call to `getCanonicalFile()` resolves symbolic links and normalizes path separators. The prefix check ensures the resolved path falls within the permitted base directory, preventing both `../` traversal and absolute path injection attacks.

## Explanation

The vulnerability arises from trusting user input to construct file system paths without validation. Path traversal occurs when special sequences like `..` are used to navigate outside the intended directory. Using canonical paths eliminates path normalization ambiguities (symbolic links, `.`, `..`, redundant separators), and validating that the resolved path is contained within the base directory enforces the restriction. This prevents an attacker from escaping the document store, whether through relative traversal (`../../../etc/passwd`) or symbolic link attacks.
