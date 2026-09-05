## Verdict

Exploitable.

## Source

Case17A.java line 16 passes `data = "foo"` to Case17B.handleSink(). The test case simulates this with a constant, but the `data` parameter represents untrusted external input that reaches the LDAP query sink.

## Fix

**Vulnerable code (Case17B.java lines 29–32):**
```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[] { data }, new SearchControls());
```

## Explanation

The vulnerability lies in constructing the LDAP filter by concatenating untrusted `data` directly into the filter string at line 29. An attacker controlling `data` can inject LDAP metacharacters—such as `)`, `(`, or `*`—to manipulate the query and access unauthorized directory entries. The fix replaces string concatenation with JNDI's parameterized `DirContext.search()` overload. The placeholder `{0}` marks where user input goes, and the data is passed separately via the `filterArgs` parameter as a String. JNDI automatically escapes the argument according to RFC 4515, neutralizing all LDAP metacharacters before the filter reaches the directory. The `SearchControls()` parameter is required when using the `filterArgs` overload; passing a default instance is safe for standard searches.

## Behaviour changes

The call now passes `filterArgs` and `SearchControls` parameters where the original passed `null`. This is not a silent behaviour change: the JNDI search overload signature changed from `search(name, filter, cons)` to `search(name, filterExpr, filterArgs, cons)`, and `cons` becomes mandatory. A default `SearchControls()` object preserves the original search scope (SUBTREE), size limit, time limit, and other defaults; the filter expression is interpreted the same way; and results are returned identically. The only behaviour difference is that injected metacharacters in `data` no longer modify the filter—they are treated as literal string values, which is the intended fix.
