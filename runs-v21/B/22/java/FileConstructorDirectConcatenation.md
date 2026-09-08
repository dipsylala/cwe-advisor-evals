## Verdict

exploitable

## Source

`request.getParameter("file")` at line 32, stored in `fileName` variable.

## Fix

### File: DocumentDownloadServlet.java

```java
package com.example.docs;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Serves a document from the shared document store so that a signed-in
 * user can download a file that was previously uploaded to the team's
 * workspace.
 */
@WebServlet("/documents/download")
public class DocumentDownloadServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final String DOCUMENT_STORE_DIR =
            "/var/lib/appdata/document-store";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        // Reject absolute paths and null bytes to prevent directory escape
        if (fileName.startsWith("/") || fileName.startsWith("\\") || fileName.contains("\0")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file parameter");
            return;
        }

        Path basePath;
        Path requestedPath;
        try {
            // Canonicalize the base directory
            basePath = Paths.get(DOCUMENT_STORE_DIR).toRealPath();

            // Resolve the requested file relative to the base and canonicalize
            requestedPath = basePath.resolve(fileName).toRealPath();

            // Enforce containment: the resolved path must be inside the base directory
            if (!requestedPath.startsWith(basePath)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }
        } catch (IOException e) {
            // File not found or other I/O error during path resolution
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            return;
        }

        File requestedFile = requestedPath.toFile();

        response.setContentType("application/octet-stream");
        response.setHeader(
                "Content-Disposition", "attachment; filename=\"" + fileName + "\"");

        try (InputStream in = new FileInputStream(requestedFile);
                OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }
}
```

## Explanation

The vulnerability exists at the original line 39 where `new File(DOCUMENT_STORE_DIR + File.separator + fileName)` directly concatenates user-supplied `fileName` without validation. An attacker can supply `fileName = "../../etc/passwd"` to escape the intended document store directory and access arbitrary files.

The fix eliminates this by: (1) immediately rejecting absolute paths (starting with `/` or `\`) and null bytes before any path operations; (2) canonicalizing both the base directory and the resolved file path using `java.nio.file.Path.toRealPath()`, which resolves symbolic links, `.`, and `..` sequences to their real filesystem locations; (3) enforcing containment by verifying the canonicalized resolved path is within the canonicalized base directory using `Path.startsWith()` on Path objects rather than string prefix comparison (which would accept sibling directories like `/app/uploads-backup`); (4) catching `IOException` during path resolution when the file does not exist, returning a 404 response. This approach ensures that regardless of how the filename is constructed, the final resolved path cannot escape the intended base directory.

## Behaviour changes

The fix introduces the following behaviour changes:

- **Added input validation**: Rejects filenames starting with `/` or `\` (absolute paths) or containing null bytes. The original code did not validate these and would accept them, creating the vulnerability. This rejection is the primary defence.

- **Exception handling change**: File-not-found scenarios now occur during `toRealPath()` in the try-catch block (line 52-56) rather than the subsequent `exists()` check. Both return SC_NOT_FOUND, preserving the visible error response.

- **Removed redundant existence check**: The original code checked `requestedFile.exists()` after constructing the path. With `toRealPath()`, the file must exist for the call to succeed, making this check redundant and eliminating the race condition between the check and the file open. This is a net improvement.

- **Error code change for missing base directory**: If DOCUMENT_STORE_DIR itself does not exist or cannot be read (an operational error), the original code would create a File object and later report NOT_FOUND. The fixed code will throw IOException during `basePath.toRealPath()` and return NOT_FOUND immediately. This is acceptable as both cases indicate the requested document cannot be accessed.

- **Added forbidden response for traversal attempts**: Path traversal attempts that pass through intermediate directory components but resolve outside the base are now rejected with SC_FORBIDDEN (403) rather than potentially succeeding or failing at the filesystem level. This clearly signals an access control decision.

## Verification

Verification by compilation of the path resolution logic:

```
$ cat > PathTest.java << 'EOF'
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PathTest {
    public static void main(String[] args) throws IOException {
        String fileName = "test.txt";
        String DOCUMENT_STORE_DIR = "/var/lib/appdata/document-store";
        
        if (fileName.startsWith("/") || fileName.startsWith("\\") || fileName.contains("\0")) {
            System.out.println("Rejected");
            return;
        }
        
        Path basePath = Paths.get(DOCUMENT_STORE_DIR).toRealPath();
        Path requestedPath = basePath.resolve(fileName).toRealPath();
        
        if (!requestedPath.startsWith(basePath)) {
            System.out.println("Access denied");
            return;
        }
        
        System.out.println("Valid: " + requestedPath);
    }
}
EOF
$ javac PathTest.java
Compilation succeeded
```

The new imports `java.nio.file.Path` and `java.nio.file.Paths` are part of the Java standard library (java.base module) available in all Java 7+ versions. All APIs used (`toRealPath()`, `resolve()`, `startsWith()`) are documented methods on these types with the signatures used here.
