## Verdict

Exploitable. Untrusted user input from the HTTP request parameter is directly concatenated into an LDAP filter string and executed via `DirContext.search()` without any escaping or validation.

## Source

Line 44: `String param = request.getParameter("BenchmarkTest00021");`

The parameter value is read directly from the HTTP request with no validation.

## Fix

**Vulnerable code (line 54-55):**
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
```

**Fixed code:**
```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
```

The uid parameter is now passed as a separate filter argument via the `Object[]` array rather than concatenated into the filter string. JNDI's `DirContext.search()` method automatically applies RFC 4515 escaping to string-valued arguments in the filterArgs array, neutralizing LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) that an attacker might inject.

## Explanation

LDAP Injection occurs when untrusted input is concatenated into an LDAP filter string without escaping. An attacker can inject metacharacters like `)` and `(` to alter the query logic. For example, input like `*)(|(uid=*` would modify the filter to `(&(objectclass=person))(|(uid=*)(|(uid=*)(street=...))`, effectively removing the uid condition and creating a match-anything clause.

The fix leverages JNDI's parameterized filter API, which separates filter structure from user data. By using placeholders `{0}` and `{1}` and passing both `param` and the hardcoded street value through the `filterArgs` array, JNDI's internal RFC 4515 escaper neutralizes any special LDAP characters before the query is sent to the directory.

## Behaviour changes

None. The fixed code maintains identical search semantics - it searches for users with `objectclass=person` where either `uid` matches the parameter or `street` equals "The streetz 4 Ms bar". The `DirContext.search()` method call signature and SearchControls configuration remain unchanged. The fix only changes how the filter value is passed (concatenation → parameterized escaping) and applies no new defaults or altered return handling.
