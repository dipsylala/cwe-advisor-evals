## Verdict

Confirmed. `import_template_bundle` extracts a customer-supplied tarball with `tarfile.open(staged_path).extractall(workspace_dir)` and no member filtering. A tar entry with a path such as `../../etc/cron.d/x` (or an absolute path, or a symlink pointing outside the workspace) is written wherever its name resolves to, escaping the per-tenant workspace directory. `extractall()` with no `filter` argument does not validate member names against the destination directory.

## Source

The tarball itself is attacker-controlled: it arrives as `request.files["bundle"]` (the `bundle` multipart upload), is saved unmodified to `staged_path`, and every member name inside it is opened by `tarfile.open(staged_path)` and extracted by `extractall(workspace_dir)` at line 39. The tenant only controls the outer file name (checked for a `.tar.gz` suffix) and `tenant_id`; the archive's internal member paths are not checked at all, and those member paths are the sink's real input.

## Fix

### File: TarfileExtractallNoFilter.py

```python
"""Bundle-import endpoint for the reporting service.

Runtime: Python 3.11 (see runtime.txt / Dockerfile base image
python:3.11-slim). Deployed archives are customer-supplied tarballs
containing a set of report templates that get unpacked into a
per-tenant workspace directory before the template engine loads them.
"""

import os
import tarfile
import uuid

from flask import Flask, request, jsonify

app = Flask(__name__)

WORKSPACE_ROOT = "/srv/app/tenant-workspaces"


def _tenant_workspace_dir(tenant_id: str) -> str:
    workspace_dir = os.path.join(WORKSPACE_ROOT, tenant_id)
    os.makedirs(workspace_dir, exist_ok=True)
    return workspace_dir


@app.route("/api/tenants/<tenant_id>/templates/import", methods=["POST"])
def import_template_bundle(tenant_id):
    upload = request.files.get("bundle")
    if upload is None or not upload.filename.endswith(".tar.gz"):
        return jsonify({"error": "expected a .tar.gz bundle upload"}), 400

    workspace_dir = _tenant_workspace_dir(tenant_id)

    staged_name = f"{uuid.uuid4().hex}.tar.gz"
    staged_path = os.path.join(workspace_dir, staged_name)
    upload.save(staged_path)

    with tarfile.open(staged_path) as bundle:
        bundle.extractall(workspace_dir, filter="data")

    os.remove(staged_path)

    return jsonify({"tenant": tenant_id, "workspace": workspace_dir}), 200


if __name__ == "__main__":
    app.run()
```

## Explanation

`tarfile.extractall()` accepts a `filter` argument (PEP 706) that validates every member before it is written: the built-in `"data"` filter rejects members whose resolved path would land outside the destination directory, strips absolute paths and `..` traversal segments, refuses device/character-special files, and drops dangerous permission bits and symlinks that point outside the extraction root - raising `tarfile.OutsideDestinationError` (a subclass of `tarfile.FilterError`) instead of writing the file. This directly closes the traversal: a member named `../../etc/cron.d/x` or `/etc/passwd` is rejected rather than extracted relative to `workspace_dir`.

`filter="data"` is available on Python 3.11 without any upgrade: PEP 706 was backported as a security fix to 3.11.4, 3.10.12, 3.9.17, and 3.8.17, and the target runtime is `python:3.11-slim`, which tracks the latest 3.11.x patch release. From Python 3.14 onward `"data"` is the extraction default even without passing `filter`; passing it explicitly here keeps the code correct on the stated 3.11 runtime and self-documenting on any version.

`"data"` is the correct filter for this use case rather than the more permissive `"tar"` filter: the archives are customer-supplied templates for a template engine to read, not an installer payload that needs to preserve device nodes, absolute paths, or unusual permission bits. `"data"` also normalizes ownership and clears `setuid`/`setgid`/sticky bits, which is appropriate for content that will later be read back by the reporting service rather than executed with elevated permissions.

The rest of the flow is unaffected: `staged_path` itself is still built from a server-generated UUID joined under the already-created `workspace_dir`, so the staging write and the later `os.remove(staged_path)` are not part of this finding. Wrapping the open in a `with` block additionally ensures the tarfile handle is closed before the file is removed, which the original code left to garbage collection.
