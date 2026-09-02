## Verdict

exploitable (confidence: high)

- cwe_id: CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query)
- location: Case09E.java, line 32 (`directoryContext.search("", search, null)`)

## Source

`request.getParameter("name")` in `Case09A.handle()` (Case09A.java, line 16). The value is passed unmodified as the `data` parameter through `Case09B.handleSink` -> `Case09C.handleSink` -> `Case09D.handleSink` -> `Case09E.handleSink`. No validation, escaping, or transformation occurs at any hop in the chain; `data` reaches Case09E identical to the raw HTTP parameter.

In `Case09E.handleSink` (line 29) it is concatenated directly into an LDAP filter string:

```
String search = "(cn=" + data + ")";
```

and that string is passed as the filter argument to `DirContext.search` at line 32, the reported sink. An attacker-controlled `name` parameter containing `)`, `(`, or `*` can close the `cn` clause, inject additional filter terms, or turn the equality test into a wildcard match, altering which directory entries are returned.

Sink contract (`DirContext.search(String name, String filter, SearchControls cons)`):
- Returns a `NamingEnumeration<SearchResult>` that the caller iterates, writing every returned attribute value via `IO.writeLine`.
- Discards nothing beyond what the original code already discards.
- Leaves the base name (`""`, search root) and `SearchControls` (`null`, provider default) implicit; the fix does not touch either.
- On `NamingException` the existing code logs a warning and falls through to close the context in `finally`; failure behaviour is unchanged.

## Fix

No third-party library is required or recommended; the fix is RFC 4515 filter-value escaping applied at the point the value is concatenated into the filter, using the standard `javax.naming` APIs already in use.

Vulnerable code (Case09E.java, lines 29-32):

```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

Fixed code:

```java
String search = "(cn=" + escapeLDAPSearchFilter(data) + ")";

NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

with an escaping helper added to the class:

```java
private static String escapeLDAPSearchFilter(String filter)
{
    StringBuilder escaped = new StringBuilder();
    for (int i = 0; i < filter.length(); i++)
    {
        char currentChar = filter.charAt(i);
        switch (currentChar)
        {
            case '\\':
                escaped.append("\\5c");
                break;
            case '*':
                escaped.append("\\2a");
                break;
            case '(':
                escaped.append("\\28");
                break;
            case ')':
                escaped.append("\\29");
                break;
            case '\u0000':
                escaped.append("\\00");
                break;
            default:
                escaped.append(currentChar);
        }
    }
    return escaped.toString();
}
```

## Explanation

The fix escapes every RFC 4515 metacharacter (`\`, `*`, `(`, `)`, NUL) in the user-supplied `data` value before it is concatenated into the filter string, converting each into its two-digit hex escape sequence. This is filter-value escaping, not DN escaping (a different rule set, RFC 4514, not applicable here since `data` is used only inside the filter, not as a name/DN). Because the escaping is applied to `data` alone and not to the surrounding `(cn=` / `)` literals the fix itself supplies, an attacker-supplied `)` or `(` can no longer close the `cn` clause or open a new one, and a bare `*` can no longer turn the equality test into a wildcard - all three are rendered as literal characters the LDAP server matches against the `cn` attribute's actual value rather than as filter syntax. The base name (`""`) and null `SearchControls` are left exactly as in the original code, so search scope is unchanged.

## Behaviour changes

- For a `name` value containing no LDAP metacharacters, the escaping function returns the input unchanged, so search results for legitimate queries are identical to before.
- For a `name` value containing `\`, `*`, `(`, `)`, or NUL, the search now treats those characters as literal data to match against the `cn` attribute instead of as filter syntax. This is the intended effect of the fix: it forecloses the injection, and it also means a legitimate `cn` value that happens to contain one of these characters (e.g. a literal `*` in a name) is now matched literally rather than being interpreted as a wildcard - the correct behaviour for a search intended to match that exact value.
- No other argument, return value, or error-handling path was changed: the base DN (`""`), `SearchControls` (`null`), result iteration, logging, and context-close logic in `finally` are all unmodified.
