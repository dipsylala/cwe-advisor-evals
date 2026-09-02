## Verdict

Exploitable. Confidence: high.

## Source

`request.getParameter("name")` in `Case08A.handle()` (Case08A.java:16), assigned to `data` and
passed unmodified through `Case08B.handleSink()` (Case08B.java:13) and `Case08C.handleSink()`
(Case08C.java:13) into `Case08D.handleSink()` (Case08D.java:17). No validation, encoding, or
type conversion occurs anywhere on this path.

Sink: `directoryContext.search("", search, null)` at Case08D.java:32, where `search` is built at
Case08D.java:29 as `"(cn=" + data + ")"` - untrusted input concatenated directly into an LDAP
search filter string. An attacker-supplied `name` containing `)`, `(`, or `*` can close the `cn`
clause, inject additional filter terms, or turn the equality test into a wildcard match, altering
which directory entries the search returns.

## Fix

No third-party library is needed - the fix uses the JDK's own parameterized JNDI search overload,
which escapes filter arguments per RFC 4515 automatically.

Vulnerable code (Case08D.java:29-32):

```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

Fixed code:

```java
String search = "(cn={0})";
Object[] filterArgs = new Object[] { data };
SearchControls searchControls = new SearchControls();

NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, searchControls);
```

(`SearchControls` is already reachable via the existing `import javax.naming.directory.*;` on
Case08D.java:10 - no new import is required.)

## Explanation

The filter string no longer contains the untrusted value directly. `data` is passed as a `String`
element of `filterArgs` and substituted into the `{0}` placeholder by `DirContext.search()`
itself, which JNDI's Javadoc guarantees is escaped per RFC 2254/RFC 4515 for string-valued
arguments - so a value containing `*`, `(`, `)`, `\`, or NUL is rendered as a literal `cn` value
rather than being parsed as filter syntax. This closes the injection point at its source rather
than attempting to denylist characters. The 4-argument `search(name, filterExpr, filterArgs, cons)`
overload requires a trailing `SearchControls` argument (there is no 3-argument overload that takes
`filterArgs`), so a `SearchControls` instance is now constructed explicitly.

## Behaviour changes

- `cons` argument: the original 3-argument call passed `null`, which JNDI treats as equivalent to
  a default `new SearchControls()`. The fix passes `new SearchControls()` explicitly because the
  4-argument overload requires a non-omittable trailing `SearchControls` argument and has no
  3-argument, filterArgs-accepting form. This preserves the same default search scope and
  attribute-return behaviour as before - not a behavioural change, only a syntactic one forced by
  the API shape.
- No other differences: return type, loop over `answer`, attribute enumeration, exception handling,
  and resource cleanup in the `finally` block are all unchanged.
