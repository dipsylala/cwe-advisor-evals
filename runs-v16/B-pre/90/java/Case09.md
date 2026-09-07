## Verdict

Exploitable. The code constructs an LDAP filter by concatenating untrusted user input directly into the filter string without escaping, allowing LDAP injection attacks.

## Source

The `data` parameter (line 17) passed to `handleSink(String data, HttpServletRequest request, HttpServletResponse response)` - user-controlled input from an HTTP request.

## Fix

**Vulnerable code (lines 29-32):**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
SearchControls controls = new SearchControls();

NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[]{data}, controls);
```

## Explanation

The fix replaces string concatenation with JNDI's parameterized search filter. Instead of building the filter by concatenating the user input into the string, the placeholder `{0}` marks where the value goes, and the data is passed separately via the `filterArgs` parameter as `new Object[]{data}`. JNDI's `DirContext.search()` method automatically escapes the string-valued argument according to RFC 4515, preventing metacharacters like `*`, `(`, `)`, backslash, and NUL from being interpreted as filter syntax. This also requires passing an explicit `SearchControls` argument to the four-parameter overload; the default controls apply the current scope.

## Behaviour changes

The `SearchControls` object is now explicitly instantiated with defaults. In the original code, `null` was passed as the third argument, which allowed JNDI to use its built-in defaults. The new `SearchControls()` with no arguments produces the same defaults, so there is no functional change: the search still returns all attributes, uses the default scope (ONELEVEL), and applies the same size and time limits.
