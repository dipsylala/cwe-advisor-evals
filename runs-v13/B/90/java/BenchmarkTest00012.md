## Verdict
**Exploitable - LDAP Injection via request header**

The code retrieves user input from an HTTP header, URL-decodes it, and concatenates it directly into an LDAP filter string without escaping. An attacker can inject LDAP metacharacters (`*`, `(`, `)`) to break out of the intended filter logic and manipulate the directory search.

## Source
`BenchmarkTest00012.java`, line 69.

Request header `BenchmarkTest00012` → URL-decoded to `param` → concatenated into LDAP filter → passed to `DirContext.search()`.

**Data flow**:
- Line 45-48: Untrusted header read into `param`
- Line 52: URL-decoded (does not sanitize LDAP metacharacters)
- Line 60: Concatenated into filter string: `"(&(objectclass=person))(|(uid=" + param + ")(street={0}))"`
- Line 69: Filter passed to `idc.search(base, filter, filters, sc)` (sink)

## Fix
Replace lines 60–61 with:

```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
```

The parameterized `search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload automatically escapes each argument in the `filterArgs` array according to RFC 4515, preventing LDAP injection. The placeholders `{0}` and `{1}` are replaced with the escaped values of `filters[0]` and `filters[1]` respectively.

## Explanation
The vulnerability exists because user input is concatenated directly into the LDAP filter string. The fix uses JNDI's parameterized search API, which separates filter structure (the placeholders and boolean operators) from user data (the `filterArgs` array). Each value in `filterArgs` is automatically escaped by the JDK before substitution, neutralizing LDAP metacharacters like `*`, `(`, and `)`. This enforces the rule that user input cannot alter filter structure.

The existing code already used placeholders for the "street" attribute; extending that pattern to the "uid" attribute closes the injection point completely. No additional libraries or configuration are required—this is part of the standard Java JNDI API.

## Behaviour changes
The search behavior remains functionally identical:
- The search still targets the same base DN and scope
- The search still returns the same results for valid, non-malicious input
- Malicious LDAP filter syntax in the `uid` parameter is now treated as literal string data and safely escaped, preventing query manipulation
- The number and types of return attributes are unchanged
