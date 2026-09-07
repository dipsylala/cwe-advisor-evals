## Verdict

Exploitable. Untrusted user input from HTTP headers flows directly into an LDAP filter string via string concatenation, allowing attackers to inject LDAP filter metacharacters and manipulate the query structure.

## Source

**Lines 45-52:** HTTP request headers (attacker-controlled source)

```java
java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00012");
if (headers != null && headers.hasMoreElements()) {
    param = headers.nextElement(); // just grab first element
}
param = java.net.URLDecoder.decode(param, "UTF-8");
```

The `param` variable receives untrusted data from HTTP headers and is URL-decoded but not validated or escaped for LDAP context.

## Fix

**Vulnerable code (line 60, 69):**

```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};

javax.naming.directory.DirContext ctx = ads.getDirContext();
javax.naming.directory.InitialDirContext idc =
        (javax.naming.directory.InitialDirContext) ctx;
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        idc.search(base, filter, filters, sc);
```

**Fixed code:**

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

The fix replaces direct string concatenation of the untrusted `param` variable with a parameterized placeholder `{0}` in the filter string. The user input is now passed through the `filterArgs` array as the first argument. JNDI's `search(name, filterExpr, filterArgs, cons)` method automatically escapes values in the `filterArgs` array according to RFC 4515 (LDAP filter encoding rules) before substituting them into the filter expression. This prevents LDAP injection by treating user input as data rather than as part of the query syntax structure. Special LDAP characters such as `*`, `(`, `)`, `\`, and NUL are properly escaped and no longer have syntactic meaning.

## Behaviour changes

**Filter argument indexing:** The `filters` array now contains `param` as the first element (index 0) for the uid placeholder, and the street value as the second element (index 1). This is a necessary change to match the `{0}` and `{1}` placeholders in the filter string and does not affect the semantics of the search.

**LDAP character escaping:** User-supplied input is now automatically escaped by JNDI before being combined with the filter string. This is the primary security control and is transparent to the caller - legitimate input values continue to produce the same search results, but injection attempts are neutralized.

**No other changes:** The base DN, search scope, search controls, result handling, and output encoding remain identical. The search will still return the same legitimate results for valid input.
