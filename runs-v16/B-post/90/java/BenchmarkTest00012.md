## Verdict

**CONFIRMED: CWE-90 (LDAP Injection)** - The `param` value, sourced from untrusted request headers and URL-decoded without validation, is concatenated directly into the LDAP filter string on line 60. Although the code calls the parameterized `DirContext.search()` overload with `filterArgs`, this only protects the `{0}` placeholder for the "street" attribute, not the embedded `param` value. An attacker can inject LDAP metacharacters (`*`, `)`, `(`, `\`, NUL) into the UID filter component to modify the query structure, bypass authentication checks, or enumerate directory entries.

## Source

**Data flow:**
1. Line 45: `request.getHeaders("BenchmarkTest00012")` retrieves untrusted HTTP headers
2. Line 48: First header value is extracted without validation
3. Line 52: URL-decoded via `URLDecoder.decode()` (only decoding, not validation)
4. Line 60: Concatenated directly into LDAP filter string: `"(&(objectclass=person))(|(uid=" + param + ")(street={0}))"`
5. Line 69: Passed to `idc.search()` as the filter expression

## Fix

Replace line 60-61 from:
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
```

To:
```java
String filter = "(&(objectclass=person))(|(uid={1})(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar", param};
```

Line 69 remains unchanged and continues to call:
```java
idc.search(base, filter, filters, sc);
```

## Explanation

The root cause is separating placeholder `{0}` for one parameter while concatenating `param` directly. JNDI's parameterized `DirContext.search(name, filterExpr, filterArgs, cons)` overload escapes each value in the `filterArgs` array per RFC 4515 before substituting it into placeholder positions. This escaping covers all LDAP filter metacharacters: `*` (wildcard), `(` and `)` (grouping), backslash (escape), and NUL.

By moving `param` into the `filterArgs` array as a placeholder replacement (here, position `{1}`), JNDI's internal escaping neutralizes any injected metacharacters. For example, an attacker's payload `*)(|(uid=*` becomes the literal string `\2a\29\28\7c\28\75\69\64\3d\2a` in the filter, which no longer closes or opens LDAP clauses.

Spring LDAP's `LdapQueryBuilder` is an alternative; it applies the same escaping automatically and is more readable, but JNDI's parameterized overload is available without extra dependencies.

## Behaviour changes

**Before fix:** The filter remains vulnerable to injection. For example, `param = "admin*"` becomes `uid=admin*`, which matches any UID starting with "admin". A more dangerous payload like `admin)(&` alters the filter structure to `uid=admin)(&`, closing the uid equality test prematurely and potentially altering the query logic. A bare `*` in `param` creates a wildcard match returning all users.

**After fix:** All values in `filterArgs` are escaped before JNDI substitutes them, so:
- `param = "admin*"` is escaped to `admin\2a` and the filter becomes `uid=admin\2a`, which searches for a literal UID containing an asterisk character, not a wildcard
- `param = "admin)(&"` is escaped and becomes a literal search string; the metacharacters do not alter filter structure
- `param = "*"` is escaped to `\2a` and searches for a literal asterisk, not a presence match

The search still executes and returns matching results, but the attacker can no longer manipulate the query logic or access unauthorized directory entries. The fix preserves functional correctness while eliminating the injection vector.
