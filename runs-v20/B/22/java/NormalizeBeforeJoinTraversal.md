## Verdict

exploitable (confidence: high)

- cwe_id: CWE-22
- location: `ReportFileReader.java`, line 15 (sink: `Files.readAllBytes(target)`)

## Source

`userSuppliedPath`, the `String` parameter to `readReport(String userSuppliedPath)`. It is attacker-controlled at the method boundary (the caller is not shown, but the parameter is treated as a raw, unvalidated path fragment).

Flow: `userSuppliedPath` -> `Path.of(userSuppliedPath).normalize()` (line 11, string-only rewrite) -> `.toString()` -> `cleaned` -> `BASE_DIR.resolve(cleaned)` (line 12) -> `target` -> `Files.readAllBytes(target)` (line 15, sink).

The only transform applied before the sink is `Path.normalize()`, which is purely lexical: it collapses `.`/`..` segments in the string without touching the filesystem and does not follow symlinks. It does not enforce containment, and it does not stop `resolve()` from being handed an absolute path. Two escapes both survive to the sink:

- A relative traversal such as `../../etc/passwd`: `normalize()` has no leading segment to cancel against, so it leaves the `..` sequence intact, and `BASE_DIR.resolve(...)` walks the resolved path outside `/var/app-data/reports`.
- An absolute path such as `/etc/passwd`: per the `Path.resolve(Path)` contract, when the argument is absolute the base is discarded entirely and the argument is returned as-is - `BASE_DIR` never applies at all.

No check anywhere compares the result against `BASE_DIR`, so both reach `Files.readAllBytes()` unconstrained. The path is genuinely exploitable as reported.

## Fix

### File: ReportFileReader.java

```java
package cases.pathtraversal;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ReportFileReader {
    private static final Path BASE_DIR = Path.of("/var/app-data/reports");

    public byte[] readReport(String userSuppliedPath) throws IOException {
        Path candidate = Path.of(userSuppliedPath);
        if (candidate.isAbsolute()) {
            throw new IOException("Absolute paths are not permitted");
        }

        Path base = BASE_DIR.toRealPath();
        Path target = base.resolve(candidate).toRealPath();

        if (!target.startsWith(base)) {
            throw new IOException("Resolved path escapes the reports directory");
        }

        return Files.readAllBytes(target);
    }
}
```

## Explanation

The vulnerable code canonicalized with `Path.normalize()`, which only rewrites the path string and cannot detect an absolute-path override or a symlink planted inside the base directory that points elsewhere. The fix replaces it with `Path.toRealPath()`, which resolves the path against the actual filesystem (following symlinks) and requires the target to exist - the same existence requirement `Files.readAllBytes()` already imposes, so no new failure mode is introduced by that requirement. Both `BASE_DIR` and the candidate target are canonicalized with the same method so they are comparable, and containment is enforced with `Path.startsWith(Path)` on the resulting `Path` objects (never a string prefix, which a sibling directory like `/var/app-data/reports-secret` would defeat). An explicit `candidate.isAbsolute()` check runs first because `Path.resolve()` silently discards the base for an absolute argument - `toRealPath()` plus `startsWith()` still catches an absolute escape after the fact, but rejecting it up front matches the language guidance and gives a clearer failure reason. The resolved `target` produced by this check is the same `Path` instance passed to `Files.readAllBytes()`, so the value validated is the value used.

Null-byte input is already rejected by the JDK's Unix path provider, which throws `InvalidPathException` from `Path.of()` for an embedded NUL character - both the original and fixed code inherit that behavior unchanged, so no separate check was added for it.

## Behaviour changes

- **New rejection paths**: an absolute `userSuppliedPath`, or one that traversal-resolves outside `BASE_DIR`, now throws `IOException` instead of silently reading the out-of-bounds file (previously a successful, unintended read) or failing later with a generic `NoSuchFileException`. This is the intended effect of closing the weakness, not a side effect.
- **Symlink handling**: `toRealPath()` follows symbolic links, where the original `normalize()` did not. A symlink placed inside `/var/app-data/reports` that points outside it is now blocked by the containment check; previously it would have been followed and read. This is a deliberate hardening consistent with the loaded guidance and not expected to affect legitimate reports, which are ordinary files.
- **Existence requirement moved earlier**: `toRealPath()` throws `IOException` if the resolved file does not exist, at the same point `Files.readAllBytes()` would already have thrown for a missing file. No new class of failure for a legitimate, existing report path.
- **Return value and success-path output**: unchanged - `Files.readAllBytes(target)` is still the sink, still returns the same `byte[]`, and the method's public signature (`throws IOException`) is unchanged.
- No allowlist, extension restriction, or indirect-reference mapping was introduced; the application does not define a permitted-file list in the given code, so containment alone is the fix, per the loaded guidance's instruction not to invent a restriction the application doesn't already define.

## Verification

Compiled the fixed file standalone with `javac` (JDK 26, `javac -d out cases/pathtraversal/ReportFileReader.java`) after placing it in the required `cases.pathtraversal` package directory in a scratch location - compiled cleanly with no errors or warnings. Every symbol used beyond the original file (`Path.isAbsolute()`, `Path.toRealPath()`, `Path.resolve(Path)`, `Path.startsWith(Path)`) is a standard `java.nio.file.Path` instance method already imported via the pre-existing `import java.nio.file.Path;`; no new imports were needed and none were added.

## Assumptions

- `BASE_DIR` (`/var/app-data/reports`) is assumed to exist and be readable at call time in the deployed environment, matching the original code's implicit assumption (the original would already fail on any read attempt if it did not).
- No extension or filename allowlist was added because the given source has no existing notion of "permitted file names" to enforce; per the loaded guidance, containment is the complete fix here and inventing a list was avoided.
