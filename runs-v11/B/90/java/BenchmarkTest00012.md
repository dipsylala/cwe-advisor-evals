## Verdict

Exploitable. The untrusted parameter from the HTTP header is concatenated directly into an LDAP filter string without escaping, allowing an attacker to inject LDAP metacharacters.

## Source

HTTP request header `BenchmarkTest00012` (line 45-48), URL-decoded at line 52 into the `param` variable, which is attacker-controlled.

## Fix

**Vulnerable code (lines 60-61, 69):**
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
// ...
idc.search(base, filter, filters, sc);
```

**Fixed code:**
```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
// ...
idc.search(base, filter, filters, sc);
```

## Explanation

The vulnerability is fixed by replacing string concatenation with JNDI's parameterized filter API. Instead of concatenating the untrusted `param` value directly into the filter string, it is passed via the `filterArgs` array (now at index 0). JNDI's `search()` method automatically escapes each string-valued argument according to RFC 4515, neutralizing LDAP metacharacters such as `*`, `(`, `)`, and backslash. The filter string now contains placeholders (`{0}` for uid, `{1}` for street) that the JNDI framework safely substitutes with escaped values. This prevents an attacker from closing the uid filter clause with `)` and injecting additional filter logic via `(|(uid=*))` or similar payloads.

## Behaviour changes

None. The `search()` method signature and invocation remain unchanged. The search scope, search controls, and return results are identical. Only the filter parameter handling changes from direct concatenation to parameterized substitution with automatic escaping.
