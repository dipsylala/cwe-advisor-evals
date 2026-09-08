## Verdict

Confirmed. The finding is real.

## Source

`filenames` (parameter of `create_backup_archive`) is attacker-influenced input: any caller-supplied list of file names ends up concatenated directly into the argument vector passed to `tar`.

## Fix

### File: backup.py

```python
import subprocess


def create_backup_archive(archive_path, filenames):
    for name in filenames:
        if name.startswith("-"):
            raise ValueError(f"invalid filename: {name!r}")

    command = ["tar", "czf", archive_path, "--"]
    command.extend(filenames)

    subprocess.run(command, shell=False, check=True)
```

## Explanation

`shell=False` with an argument list rules out shell metacharacter injection, but it does not rule out *option* (flag) injection. `tar` parses every argument that begins with `-` as an option regardless of its position in the argument vector, so a crafted "filename" is not a fixed operand here - it is attacker-controlled data flowing straight into `tar`'s own option parser.

GNU `tar` accepts `--checkpoint=N` and `--checkpoint-action=exec=COMMAND`, which runs `COMMAND` via the shell every N checkpoints while the archive is being written. If `filenames` contains something like `--checkpoint=1` and `--checkpoint-action=exec=sh shell.sh` (with `shell.sh` itself supplied as another "filename" entry), `tar` treats these as options rather than files to archive, and executes the attacker-supplied command as a side effect of running `czf` - full command execution even though no shell ever parses the joined command line.

The fix has two parts:

1. **`--` end-of-options marker.** Inserting `--` before the file list is the authoritative fix: it tells `tar`'s own argument parser that everything after it is a positional operand (a file name), never an option, no matter what it starts with. This closes the injection at the point the untrusted values are consumed, which is where CWE-78 remediation belongs.
2. **Reject leading-dash names up front.** This is defense in depth, not the primary control - it also gives a clear, immediate error instead of a confusing `tar` failure or non-obvious behavior for a filename that genuinely (if unusually) starts with `-`. It is a rejection, not a strip/sanitize: a stripped or reordered value could still collide with `tar` semantics, whereas rejecting outright avoids ever presenting `tar` with an ambiguous argument.

The original `shell=False`, list-form invocation is otherwise correct and is preserved unchanged.
