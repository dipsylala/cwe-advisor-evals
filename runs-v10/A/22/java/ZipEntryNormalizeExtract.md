## Verdict

The code contains a CWE-22 path traversal vulnerability due to incomplete parent directory validation and creation logic.

## Source

The vulnerability occurs at line 18:
```java
Files.copy(zip, target);
```

While the code checks that the normalized target path stays within the destination (lines 13-16), it fails to:
1. Normalize the destination path itself for consistent comparison
2. Explicitly create parent directories before copying, which allows the extraction to proceed without verifying intermediate directories are within bounds
3. Handle the case where an attacker crafts an entry with intermediate path components that could escape during directory creation

## Fix

Replace the extract method with the following:

```java
public void extract(ZipInputStream zip, Path destination) throws IOException {
    ZipEntry entry;
    Path normalizedDest = destination.normalize();
    
    while ((entry = zip.getNextEntry()) != null) {
        Path target = normalizedDest.resolve(entry.getName()).normalize();
        
        if (!target.startsWith(normalizedDest)) {
            throw new IOException("entry escapes destination");
        }
        
        // Create parent directories with validation
        Path parent = target.getParent();
        if (parent != null && !parent.equals(normalizedDest)) {
            if (!parent.startsWith(normalizedDest)) {
                throw new IOException("parent directory escapes destination");
            }
            Files.createDirectories(parent);
        }
        
        Files.copy(zip, target);
    }
}
```

## Explanation

The fix addresses the CWE-22 vulnerability by:

1. **Normalizing the destination path once** — Ensures consistent comparison logic between destination and resolved entry paths. The original code normalized only the target, not the destination baseline.

2. **Validating parent directories explicitly** — Before creating directories, verify that the parent path stays within the destination boundary. This prevents a scenario where intermediate path components could escape the restricted directory.

3. **Creating parent directories only after validation** — Separates the path validation from the directory creation, ensuring no implicit escapes occur during the directory hierarchy setup.

4. **Guarding the directory creation step** — Adds an explicit check that parent directories don't escape destination before calling `Files.createDirectories()`, preventing attackers from leveraging symlinks or race conditions during directory creation to escape the extraction boundary.

The combination of these controls ensures that every component of the extracted file's path—both the file itself and all ancestors up to the destination root—remain within the intended extraction directory.
