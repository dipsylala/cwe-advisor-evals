## Verdict

The finding is confirmed. The `filenames` parameter contains untrusted data that flows directly into the subprocess command array without validation. While `shell=False` prevents shell injection, it does not prevent argument injection—tar interprets arguments starting with `-` as options, allowing attackers to inject arbitrary tar options (e.g., `--checkpoint=...` for command execution, `-C` to change directory, `-I` to specify a custom decompression program).

## Source

The `filenames` parameter (line 4) is untrusted user input. It is extended directly into the command array (line 6) without validation.

## Fix

Replace `subprocess.run()` with Python's native `tarfile` module, eliminating the subprocess sink entirely:

```python
import tarfile

def create_backup_archive(archive_path, filenames):
    with tarfile.open(archive_path, "w:gz") as tar:
        for filename in filenames:
            tar.add(filename)
```

## Explanation

The `tarfile` module is Python's native library for creating and manipulating tar archives. Using it eliminates the subprocess sink entirely, preventing both shell injection and argument injection. The module handles all tar operations programmatically—no external tar command is invoked. Files are added to the archive via the `tar.add()` method, where the filename parameter is treated as a filesystem path to archive, not as a command-line argument subject to option interpretation.

## Behaviour changes

- The subprocess.run() call is removed; no subprocess is spawned
- The archive is created with gzip compression (mode `"w:gz"`) matching the original `tar czf` behavior
- Return value: No return value is produced (the original code ignored the return value with `check=True`)
- Exception handling: FileNotFoundError or tarfile.TarError exceptions replace CalledProcessError on failure
- No implicit arguments passed: tarfile operates independently of subprocess environment variables or working directory contamination
