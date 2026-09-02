## Verdict
The code validates the Content-Type header against an allowlist but fails to validate the actual filename, creating a CWE-434 unrestricted upload vulnerability. An attacker can upload executable files by using a trusted Content-Type header while providing a malicious filename (e.g., `shell.php`, `../../../etc/passwd`), bypassing file type restrictions and enabling path traversal, code execution, or file overwrite attacks.

## Source
Line 13 accepts the filename directly from the user-supplied file object without validation:
```python
filename = file.filename
```

Line 18 saves the file using this untrusted filename:
```python
file.save(destination)
```

Although line 15 checks the Content-Type header, this is insufficient because:
- The Content-Type header can be spoofed by the client
- The filename is never validated, allowing path traversal sequences and dangerous extensions

## Fix
```python
from flask import Flask, request
import os
import secrets
from pathlib import Path

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg"}
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}

@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    filename = file.filename
    
    if file.content_type in ALLOWED_CONTENT_TYPES:
        # Validate file extension
        file_ext = Path(filename).suffix.lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            return {"status": "rejected", "error": "invalid extension"}, 400
        
        # Generate a safe, unpredictable filename
        safe_filename = f"{secrets.token_hex(16)}{file_ext}"
        destination = os.path.join(UPLOAD_DIR, safe_filename)
        
        file.save(destination)
        return {"status": "ok", "path": destination}, 200
    
    return {"status": "rejected"}, 400

if __name__ == "__main__":
    app.run()
```

## Explanation
The fix addresses CWE-434 by implementing multiple layers of validation:

1. **Extension allowlist**: Validate the file extension against a whitelist of safe extensions (`ALLOWED_EXTENSIONS`), rejecting requests with dangerous extensions like `.php`, `.exe`, `.sh`, etc.

2. **Safe filename generation**: Use `secrets.token_hex()` to generate a cryptographically random filename, completely replacing the user-supplied filename. This prevents:
   - Path traversal attacks (e.g., `../../../etc/passwd`)
   - Overwriting existing files
   - Executing uploaded files if they happen to reach a web-accessible directory
   - Filename-based attacks

3. **Preserved extension**: Retain only the validated extension from the original filename, preserving file type information while discarding the unsafe name portion.

The Content-Type header validation remains as an additional (but non-sufficient) check. The combination of strict extension validation and random filename generation effectively prevents unrestricted file upload attacks while maintaining usability.
