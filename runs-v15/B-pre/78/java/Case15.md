## Verdict

exploitable

## Source

Case15A.java, line 16: `data = "foo";` (though the parameter can accept any string from callers)

## Fix

**Vulnerable code:**
```java
String osCommand;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
    osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
} else {
    osCommand = "/bin/ls ";
}

// Vulnerable: data concatenated into command string
Process process = Runtime.getRuntime().exec(osCommand + data);
process.waitFor();
```

**Fixed code:**
```java
import java.nio.file.Files;
import java.nio.file.Paths;

// Replace the entire command execution block with:
try (var stream = Files.list(Paths.get(data))) {
    // Directory listing is performed; output discarded to match original behavior
    stream.forEach(path -> {});
} catch (java.nio.file.NoSuchFileException e) {
    // Handle missing directory
    throw new IOException("Directory not found: " + data, e);
}
```

## Explanation

The original code concatenates the untrusted `data` parameter directly into an OS command string, which is then executed via `Runtime.exec()`. An attacker controlling the `data` parameter could inject shell metacharacters or operators to execute arbitrary commands. The fixed code replaces the system command invocation entirely with Java's native `Files.list()` API, which performs the same directory listing operation without shell interpretation. This eliminates the injection vector completely. Note: the original code discards the directory listing output (no iteration over results), so the fixed code preserves this behavior by consuming the stream without processing entries. If the caller needs the directory contents, this should be enhanced to capture and return the listing.

## Behaviour changes

The original code returned a Process object and called waitFor() on it; the fixed code returns void. The underlying operation (directory enumeration) is identical, but if the Process return value or exit code was important to callers, that capability is lost—however, the original code was already discarding the exit code and output, so this represents no functional regression. On Windows, the fix uses Java's cross-platform path handling instead of invoking cmd.exe, eliminating platform-specific parsing differences. The fixed code will throw IOException (rather than silently fail) if the directory does not exist or is not readable, which is safer behavior.
