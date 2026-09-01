## Verdict

Confirmed. Line 32 executes an LDAP search with an unsanitized filter constructed from user-supplied data, allowing LDAP injection attacks that can alter query logic.

## Source

Line 29 concatenates untrusted input directly into an LDAP filter string:
```
String search = "(cn=" + data + ")";
```

Line 32 passes this unsanitized filter to `DirContext.search()`:
```
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

An attacker controlling `data` can inject LDAP metacharacters (`*`, `(`, `)`, `\`) to modify filter semantics—for example, `data = "*)(uid=*` produces `(cn=*)(uid=*)` which changes the search to match any entry with any uid attribute.

## Fix

Escape LDAP filter metacharacters in the user-supplied input before constructing the filter. Replace line 29 with:

```
String encodedData = data
    .replace("\\", "\\5c")  // Escape backslash first (must be first)
    .replace("*", "\\2a")   // Escape asterisk
    .replace("(", "\\28")   // Escape left parenthesis
    .replace(")", "\\29")   // Escape right parenthesis
    .replace("\0", "\\00"); // Escape null character

String search = "(cn=" + encodedData + ")";
```

This encoding follows RFC 2254 and ensures that special characters in user input are treated as literal filter value data, not as LDAP syntax.

## Explanation

LDAP filter strings use parentheses, asterisks, and backslashes as operators. Without escaping, an attacker can close the current expression and inject new ones. The fix encodes each metacharacter as a backslash-prefixed hex sequence (e.g., `*` → `\2a`), converting them from operators to literal characters that represent the value the developer intended to search for. Backslash must be escaped first to avoid double-escaping the escape sequences themselves.
