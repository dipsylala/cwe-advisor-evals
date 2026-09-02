## Verdict

- CWE-90 (LDAP Injection)
- Verdict: exploitable
- Confidence: high
- Location: `BenchmarkTest00044.java`, doPost, filter built at line 56, sink at line 60

## Source

- Source: `request.getParameterValues("BenchmarkTest00044")` (line 44) - an HTTP request parameter, attacker-controlled, assigned to `param` with no validation or encoding.
- Flow: `param` is concatenated directly into an LDAP search filter string at line 56 (`"(&(objectclass=person)(uid=" + param + "))"`), and that string is passed unmodified to the sink.
- Sink: `ctx.search(base, filter, sc)` (line 60), the 3-argument `DirContext.search(Name/String, String filterExpr, SearchControls)` overload, which parses `filter` as a literal LDAP filter expression.
- Nothing on this path validates, allowlists, or escapes `param` before it reaches the filter string, and the filter itself is passed to `search()` unparameterized, so an attacker-supplied value containing `)`, `(`, or `*` closes the `uid` clause and injects additional filter terms or turns the lookup into a wildcard match.

## Fix

Vulnerable code (lines 56-60):

```java
String filter = "(&(objectclass=person)(uid=" + param + "))";
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        // SAST FINDING: CWE-90 (LDAP Injection) - an LDAP filter is built from request data and searched. Sink is the next statement.
        ctx.search(base, filter, sc);
```

Fixed code:

```java
String filterExpr = "(&(objectclass=person)(uid={0}))";
Object[] filterArgs = new Object[] {param};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filterExpr, filterArgs, sc);
```

The `found`-flag reporting path at lines 88-93 (`"nothing found for query: " + ... encodeForHTML(filter)`) references the local variable named `filter`; since the fix renames it to `filterExpr`, that reference must be updated to `filterExpr` (or the variable kept named `filter`) so the file still compiles - this is a mechanical rename, not a behavioural change, since `filterExpr` still contains the full filter template for the diagnostic message.

## Explanation

The vulnerability is that untrusted request data was concatenated directly into an LDAP filter string, letting an attacker inject filter metacharacters (`)`, `(`, `*`) to alter the query's logical structure or turn the equality test into a wildcard. The fix replaces the 3-argument `DirContext.search(Name, String, SearchControls)` call, which parses the filter as a literal expression, with the 4-argument `DirContext.search(Name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload. The filter template now holds only the static structure with a `{0}` placeholder in the value position, and the untrusted value is passed separately via `filterArgs`; per the JNDI Javadoc, a `String`-valued filter argument is escaped per RFC 2254/4515 by the provider before substitution, so filter-syntax characters in `param` are neutralized rather than interpreted as query structure. This is the language guidance's primary defence for this CWE and requires no new dependency.

## Behaviour changes

- None to the search semantics: the base DN, search scope (`sc`), the attribute filter logic (`objectclass=person` AND `uid=<value>`), and the returned `NamingEnumeration<SearchResult>` are unchanged - only how the `uid` value is substituted into the filter changes (parameterized instead of concatenated).
- Error/failure behaviour is unchanged: `search()` still throws `javax.naming.NamingException` on failure, still caught and rewrapped as `ServletException` by the existing `catch` block.
- The local variable holding the filter template must be renamed (or its downstream reference updated) from `filter` to `filterExpr` for the file to compile, since the "nothing found" branch (lines 88-93) reads that variable for its diagnostic message; the diagnostic text itself is unaffected, since the template string still contains the full filter shape.
