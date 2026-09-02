## Verdict

Exploitable. CWE-90 (LDAP Injection), `BenchmarkTest00012.java` line 69.

## Source

The value of the first `BenchmarkTest00012` HTTP request header (`request.getHeaders("BenchmarkTest00012")`, line 45), URL-decoded at line 52 (`param = java.net.URLDecoder.decode(param, "UTF-8")`). Fully attacker-controlled.

## Fix

Vulnerable code:

```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};

javax.naming.directory.DirContext ctx = ads.getDirContext();
javax.naming.directory.InitialDirContext idc =
        (javax.naming.directory.InitialDirContext) ctx;
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        // SAST FINDING: CWE-90 (LDAP Injection) - an LDAP filter is built from request data and searched. Sink is the next statement.
        idc.search(base, filter, filters, sc);
```

Fixed code:

```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};

javax.naming.directory.DirContext ctx = ads.getDirContext();
javax.naming.directory.InitialDirContext idc =
        (javax.naming.directory.InitialDirContext) ctx;
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        idc.search(base, filter, filters, sc);
```

## Explanation

The call already uses JNDI's parameterized `DirContext.search(name, filterExpr, filterArgs, cons)` overload, but only the `street` term was actually parameterized (`{0}`); the `uid` term was still built by directly concatenating the untrusted, URL-decoded header value into the filter string. Because `param` never passes through `filterArgs`, JNDI never gets the chance to apply its RFC 4515 escaping to it, so any `*`, `(`, `)`, or `\` in the header is interpreted as filter syntax rather than as literal search data - allowing an attacker to close the `uid` term early, inject additional filter clauses, or turn the equality test into a wildcard match. The fix keeps the same `search()` call and signature but moves `param` into the `filterArgs` array as a second placeholder (`{0}` for `uid`, `{1}` for `street`), so the JDK's own JNDI provider escapes it per RFC 4515 before the query is evaluated, closing the injection while leaving the literal search semantics unchanged for ordinary input.

## Behaviour changes

None beyond closing the weakness. The sink call (`idc.search(base, filter, filters, sc)`), its four arguments' types and positions, the returned `NamingEnumeration<SearchResult>`, the downstream result-processing loop, and the `NamingException` handling are all unchanged - only the `filter` string's placeholder numbering and the `filters` array's contents change, and both `filterArgs` values remain `String`, matching the scope of JNDI's documented per-argument escaping guarantee. For a header value containing no LDAP metacharacters, the query behaves identically to before. For a header value containing `*`, `(`, `)`, or `\`, the fixed query now treats those characters as literal data in the `uid` comparison instead of as filter syntax - this is the intended effect of the fix, not an incidental change.
