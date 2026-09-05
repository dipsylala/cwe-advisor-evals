## Verdict

**exploitable** — high confidence

The data flows from an external source (network read in Case11A) through pass-through methods to Case11D where it is used in `response.sendRedirect()` without proper validation. The current code validates URI syntax only; it does not validate that the URI points to a trusted destination.

## Source

**CWE-601: URL Redirection to Untrusted Site**

**Location:** evals/cases/601/java/Case11/Case11D.java, line 32

**Source:** External network read in Case11A (line 38: `data = readerBuffered.readLine()` from http://www.example.org)

**Data Flow Path:**
1. Case11A reads untrusted data from a network URL
2. Case11A → Case11B (pass-through, line 73)
3. Case11B → Case11C (pass-through, line 13)
4. Case11C → Case11D (pass-through, line 13)
5. Case11D (sink at line 32: `response.sendRedirect(data)`)

**Sink:** `response.sendRedirect(data)` — sends an HTTP redirect to an attacker-controlled URL

## Fix

**Vulnerable code (Case11D.java, lines 17–34):**

```java
if (data != null)
{
    
    URI uri;
    try
    {
        uri = new URI(data);
    }
    catch (URISyntaxException exceptURISyntax)
    {
        response.getWriter().write("Invalid redirect URL");
        return;
    }
    
    // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
    response.sendRedirect(data);
    return;
}
```

**Fixed code (Case11D.java, lines 17–37):**

```java
if (data != null)
{
    
    URI uri;
    try
    {
        uri = new URI(data);
    }
    catch (URISyntaxException exceptURISyntax)
    {
        response.getWriter().write("Invalid redirect URL");
        return;
    }
    
    // Validate that the redirect destination is relative (no scheme or host)
    // Reject absolute URLs and dangerous schemes like javascript: or data:
    if (uri.getHost() != null || uri.getScheme() != null)
    {
        response.getWriter().write("Invalid redirect URL");
        return;
    }
    
    // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
    response.sendRedirect(data);
    return;
}
```

## Explanation

The fix adds validation to reject any redirect URL that is not a relative path. After parsing the URI, it checks two conditions: if `uri.getHost()` is non-null (absolute URLs like `https://evil.com` or scheme-relative URLs like `//evil.com`), or if `uri.getScheme()` is non-null (dangerous schemes like `javascript:` or `data:`), the redirect is rejected and an error message is returned instead. This enforces a relative-path-only policy, allowing only context-relative redirects like `/dashboard` while blocking all external and dangerous URLs. The fix preserves the existing syntax validation (URI constructor) and error handling (returning an error message on invalid input).

## Behaviour changes

**Rejected inputs:** The fixed code now rejects any redirect URL that contains a scheme or non-null host. Examples:
- `https://evil.com/phishing` → rejected (has host and scheme)
- `//attacker.example/path` → rejected (has host, scheme-relative URL)
- `javascript:alert(1)` → rejected (has dangerous scheme)
- `data:text/html,<script>alert(1)</script>` → rejected (has dangerous scheme)

**Allowed inputs remain unchanged:** Relative paths like `/dashboard`, `../back`, `?foo=bar` continue to work as before.

**Sink contract preserved:** The method still takes a string parameter and either sends a redirect or returns an error message. The return value and exceptions remain unchanged. No parameters or defaults were modified.
