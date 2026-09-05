## Verdict

Exploitable. Untrusted user input is concatenated directly into an LDAP search filter without any escaping or parameterization, allowing an attacker to inject LDAP metacharacters and modify the query structure.

## Source

The `data` parameter passed to the `handleSink()` method at line 17 originates from external input (servlet request) and is used to construct an LDAP search filter at line 29 without sanitization.

Data flow:
- **Source**: `String data` parameter (untrusted)
- **Sink**: `directoryContext.search("", search, null)` at line 32
- **Injection point**: Line 29 concatenation `"(cn=" + data + ")"`

An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`) to:
- Close the current clause and open new ones: `foo*)(cn=* yields `(cn=foo*)(cn=*)(cn=*)`
- Create a wildcard match: `*` becomes a presence check matching all entries
- Bypass authentication or authorization checks by modifying filter logic

## Fix

**Vulnerable code (line 29-32):**
```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
Object[] filterArgs = { data };
SearchControls cons = new SearchControls();
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, cons);
```

## Explanation

The fix uses JNDI's parameterized `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload, which separates query structure from user data. The `{0}` placeholder in the filter template is replaced by the value in `filterArgs[0]`, which JNDI escapes according to RFC 4515, neutralizing all LDAP filter metacharacters. This prevents injection while preserving the intended search logic. The `SearchControls` parameter is required by this overload and provides default search scope settings matching the original call's behavior.

## Behaviour changes

None. The parameterized search preserves the original query semantics while closing the injection point. The `SearchControls()` constructor uses default values (scope `SUBTREE_SCOPE`, size/time limits, attribute return policy) that match standard JNDI behavior when `null` is passed as the controls parameter.
