## Verdict
Exploitable

## Source
User-controlled input from HTTP request parameter at line 44: `String param = request.getParameter("BenchmarkTest00021");` flows directly into LDAP filter construction.

## Fix

**Vulnerable code (line 54-59):**
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, filters, sc);
```

**Fixed code:**
```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, filters, sc);
```

## Explanation
The vulnerability arises from concatenating untrusted user input directly into an LDAP filter string. An attacker can inject LDAP metacharacters—such as `*`, `(`, `)`, or `\`—to alter the filter logic and potentially access unauthorized directory data. The fix uses JNDI's parameterized `DirContext.search()` method, which accepts filter arguments separately via the `filterArgs` parameter. JNDI automatically escapes each argument according to RFC 4515, neutralizing LDAP filter syntax and preventing injection. The filter now uses placeholder `{0}` for the user input and `{1}` for the hardcoded street value, with both values passed through the `Object[] filters` array where JNDI applies safe escaping.

## Behaviour changes
None. The parameterized search preserves the original sink contract: it still returns the same `NamingEnumeration<SearchResult>`, processes results identically, and raises the same `NamingException` on error. The only change is the mechanism by which the filter is constructed—from unsafe string concatenation to safe parameterized escaping.
