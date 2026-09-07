## Verdict
exploitable

## Source
Line 44: `String param = request.getParameter("BenchmarkTest00021");` - user-controlled input from HTTP request parameter

## Fix

**Vulnerable code (line 54 and 59):**
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        // SAST FINDING: CWE-90 (LDAP Injection) - an LDAP filter is built from request data and searched. Sink is the next statement.
        ctx.search(base, filter, filters, sc);
```

**Fixed code:**
```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filterArgs = new Object[] {param, "The streetz 4 Ms bar"};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, filterArgs, sc);
```

## Explanation
The vulnerability on line 54 occurs because the untrusted user input (`param`) is concatenated directly into the LDAP filter string, allowing an attacker to inject LDAP metacharacters like `*`, `(`, `)` to modify the search logic. For example, an input like `*)(uid=*))(|(uid=*` would alter the filter structure and potentially expose unauthorized directory entries. The fix replaces the string concatenation with JNDI's built-in parameterized search, which uses the `filterArgs` parameter to pass user input separately. JNDI automatically applies RFC 4515 escaping to all arguments in the `filterArgs` array, neutralizing LDAP syntax characters before they reach the directory server. Both `param` and the hard-coded string value are moved to the `filterArgs` array and referenced via placeholders `{0}` and `{1}` in the filter expression.

## Behaviour changes
The variable name changes from `filters` to `filterArgs` for clarity and consistency with JNDI naming conventions, but this is internal to the method and has no observable impact. The search returns the same `NamingEnumeration<SearchResult>` type and the remaining code processing results (lines 60-86) requires no changes. All exceptions and search scope behavior remain identical.
