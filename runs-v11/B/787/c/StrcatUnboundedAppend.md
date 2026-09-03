## Verdict

**Confirmed vulnerability: CWE-787 (Out-of-bounds Write)**

The `strcat(path, filename)` call at line 20 writes into a fixed 128-byte stack buffer without validating that the untrusted filename will fit. The subsequent bounds check at line 22 occurs after the overflow has already happened.

## Source

- **Source**: `filename` parameter - arrives from the multipart upload's Content-Disposition header (untrusted, no length validation)
- **Sink**: `strcat(path, filename)` at line 20
- **Data Flow**: `filename` is passed directly to strcat, which concatenates it into the fixed-size `path` buffer initialized with `"/srv/uploads/incoming/"`. The buffer has 128 bytes total; the initial string consumes ~22 bytes, leaving ~105 bytes. The test case's filename is 149 bytes, causing the write to overflow the stack buffer.

## Fix

Replace lines 19-20:

```c
    // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
    strcat(path, filename);
```

With:

```c
    // Validate that the full path fits in the buffer using strlcat
    size_t result = strlcat(path, filename, sizeof(path));
    if (result >= sizeof(path)) {
        return -1;  // Path would be truncated; reject it
    }
```

## Explanation

The original code uses `strcat()`, which writes without bounds checking and trusts that the destination has enough space. The check at line 22 (which validates `strlen(path) >= out_size`) comes too late—the buffer overflow has already occurred during the strcat call.

The fix replaces `strcat()` with `strlcat()`, which enforces bounds checking. The function takes the destination buffer size as an argument and returns the total length the concatenated string would have been (source + destination). When this return value is >= buffer size, it indicates truncation occurred, and we reject the operation immediately. This validation happens before any out-of-bounds write can occur, closing the vulnerability.

## Behaviour changes

- **Rejection of oversized filenames**: Filenames that would cause the full path to exceed 127 characters (128-byte buffer minus null terminator) are now rejected with a return value of -1, matching the caller's existing error-handling expectations.
- **No silent truncation**: The original code would silently overflow the buffer. The fixed code explicitly rejects the operation rather than proceeding with corrupted data.
- **Preserved contract**: The function still returns 0 on success and -1 on failure, maintaining compatibility with the caller at line 35.
