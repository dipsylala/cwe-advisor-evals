## Verdict
CONFIRMED - CWE-90 LDAP Injection vulnerability exists on line 54-59. User-supplied input from `request.getParameter()` is directly concatenated into an LDAP filter string without escaping or parameterization, allowing attackers to inject LDAP filter syntax and bypass authentication or alter query logic.

## Source
The vulnerability occurs in the filter construction on line 54:
```
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
```

The `param` variable originates from untrusted user input (line 44: `request.getParameter("BenchmarkTest00021")`) and is directly concatenated into the LDAP filter. While the `street` parameter uses placeholder `{0}` which is later populated via the `Object[] filters` array (parameterized), the `uid` parameter lacks this protection.

## Fix
Move the user-supplied `param` value into the parameterized `Object[]` array instead of concatenating it into the filter string:

```java
String filter = "(&(objectclass=person))(|(uid={1})(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar", param};
```

Then pass the parameterized `filters` array to `ctx.search()` exactly as already done on line 59. The LDAP API will safely escape the user-supplied values within the `Object[]` array before substituting them into the filter template, preventing injection attacks.

## Explanation
LDAP filter injection occurs when untrusted data is concatenated directly into LDAP filter syntax. An attacker can inject special LDAP characters like `*`, `(`, `)`, and `&` to alter the filter logic—for example, `uid=*))(&` would short-circuit the filter to always match.

The remediation uses LDAP's native parameterized query mechanism: define the filter template with numbered placeholders (`{0}`, `{1}`, etc.), then provide user values in the `Object[]` array passed to `search()`. The LDAP API handles escaping automatically, ensuring user input is treated as literal data, not filter syntax.

This approach maintains the exact same search behavior as the original code—searching for users with `uid` matching the request parameter OR with street matching "The streetz 4 Ms bar"—while eliminating the injection vector.
