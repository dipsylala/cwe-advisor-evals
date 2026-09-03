## Verdict

Exploitable. The `data` parameter is concatenated directly into an LDAP filter string without escaping, allowing an attacker to inject filter syntax and manipulate directory searches.

## Source

The `data` parameter passed to `handleSink()` at Case09E.java line 17 originates from an HTTP request and is untrusted.

## Fix

**Vulnerable code (line 29-32):**
```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String filterTemplate = "(cn={0})";
Object[] filterArgs = {data};
SearchControls controls = new SearchControls();
NamingEnumeration<SearchResult> answer = directoryContext.search("", filterTemplate, filterArgs, controls);
```

## Explanation

The vulnerability is closed by replacing string concatenation with JNDI's parameterized `DirContext.search()` overload that accepts `filterArgs`. When using the signature `DirContext.search(name, filterExpr, filterArgs, controls)`, JNDI automatically escapes each string-valued argument in the `filterArgs` array per RFC 4515, preventing injection of filter syntax characters like `*`, `(`, `)`, and backslash. The placeholder `{0}` in the filter template marks where the first argument will be substituted. A `SearchControls` object (using default settings) is required by this overload signature. This approach separates filter structure from user data at the JDK level, ensuring the injected value cannot modify the filter's logical structure.

## Behaviour changes

- The `DirContext.search()` call now passes a `SearchControls` object instead of `null` as the fourth argument. The default `SearchControls()` uses the same defaults as the previous implicit behavior (SUBTREE scope, no size/time limits), so functional behavior is unchanged.
- Filter string construction is replaced with parameterized substitution. To an attacker, this means LDAP metacharacters in the `data` value will no longer be interpreted as filter syntax; they will be escaped and treated as literal characters in the `cn` value match.
