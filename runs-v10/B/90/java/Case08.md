## Verdict

Exploitable. The `data` parameter from `HttpServletRequest` flows unchecked into an LDAP filter string via string concatenation, allowing injection of LDAP metacharacters to alter query logic.

## Source

The `data` parameter received from `HttpServletRequest` at line 17. This is attacker-controlled and traces directly to the LDAP filter construction without validation or encoding.

## Fix

Replace line 29-32 to use JNDI's parameterized `search()` overload, which takes filter arguments separately and applies RFC 4515 escaping automatically:

**Before:**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**After:**
```java
String filterExpr = "(cn={0})";
Object[] filterArgs = { data };

NamingEnumeration<SearchResult> answer = directoryContext.search("", filterExpr, filterArgs, new SearchControls());
```

## Explanation

The vulnerability occurs because user input is concatenated directly into an LDAP filter string. LDAP filters are parsed as expression trees, so special characters (`*`, `(`, `)`, `\`, NUL) have syntactic meaning and allow attackers to rewrite the query. The fix uses JNDI's parameterized `DirContext.search()` overload with separate `filterArgs`, which automatically escapes each argument according to RFC 4515, preventing injection by treating user input as data rather than query syntax.

## Behaviour changes

- **Method overload**: Changed from 3-argument `search(String, String, SearchControls)` to 4-argument `search(String, String, Object[], SearchControls)`. Both return `NamingEnumeration<SearchResult>` identically; subsequent result iteration and error handling are unchanged.
- **SearchControls argument**: Explicitly passed `new SearchControls()` instead of `null`. This uses the same defaults but is more explicit; no functional change to search scope, attributes, or limits.
- **Filter construction**: Filter expression is now a template with `{0}` placeholder instead of a concatenated string. User input is supplied via `filterArgs` array where JNDI applies RFC 4515 escaping.
- All other behavior preserved: same base DN (`""`), same result processing loop, same exception handling.
