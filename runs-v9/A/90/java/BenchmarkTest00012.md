## Verdict
Confirmed. `param` is taken directly from the `BenchmarkTest00012` HTTP request header, URL-decoded, and concatenated unescaped into an LDAP search filter string that is then passed to `DirContext.search()`. An attacker who controls the header can inject LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to alter the filter's logic - e.g. closing the `uid=` clause early and appending their own `(|...)` predicate - bypassing the intended query and extracting or enumerating directory records the filter was meant to restrict.

## Source
`request.getHeaders("BenchmarkTest00012")` (line 45) supplies the first header value into `param`, which is then URL-decoded at line 52 (`java.net.URLDecoder.decode(param, "UTF-8")`). Both the header and its decoded content are fully attacker-controlled.

## Fix
```java
String base = "ou=users,ou=system";
javax.naming.directory.SearchControls sc = new javax.naming.directory.SearchControls();
sc.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);

String safeParam = org.owasp.esapi.ESAPI.encoder().encodeForLDAP(param);
String filter = "(&(objectclass=person))(|(uid=" + safeParam + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
```

Only line 60 changes: the raw `param` is replaced with `safeParam`, produced by escaping LDAP filter metacharacters through `ESAPI.encoder().encodeForLDAP(String)` (the project already depends on ESAPI, used a few lines below for `encodeForHTML`). This escapes `\`, `*`, `(`, `)`, and NUL per RFC 4515 so the attacker-supplied value can only ever match as a literal `uid` value, never alter the filter's structure. The rest of the method - the `DirContext.search()` call, result iteration, and output encoding - is unchanged.

## Explanation
LDAP search filters are parsed left-to-right for the metacharacters `(`, `)`, `*`, `\`, and NUL; any of these appearing unescaped in a value lets an attacker terminate the intended clause and splice in arbitrary filter logic (e.g. `uid=*)(|(objectclass=*` to match every entry, or boolean tricks to extract attribute values one character at a time). Building the filter by string concatenation, as this code does, gives the attacker exactly that control since the header value flows in unmodified aside from URL-decoding.

Escaping with `ESAPI.encoder().encodeForLDAP()` neutralizes those characters (e.g. `*` becomes `\2a`, `(` becomes `\28`) before the value is embedded in the filter string, so it is always interpreted as a literal `uid` to search for, never as filter syntax - this is the standard LDAP-injection defense, analogous to parameterized queries for SQL, since JNDI's `DirContext.search()` has no native bind-parameter mechanism for filter values interpolated into the query text itself (the existing `{0}` substitution parameter only covers the `street` clause, not `uid`). To verify, submit a header value such as `*)(uid=*` and confirm the query now searches for the literal string rather than matching all records or altering result scope.
