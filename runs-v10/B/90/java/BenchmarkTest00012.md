## Verdict

Real issue confirmed. Untrusted HTTP header data is directly concatenated into an LDAP filter string without escaping, allowing LDAP injection attacks.

## Source

HTTP request header `BenchmarkTest00012` (line 45), extracted via `request.getHeaders()` at line 48 and URL-decoded at line 52. The value is untrusted and attacker-controlled.

## Fix

**Vulnerable code (line 60):**
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
```

**Fixed code:**
```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
```

Replace the concatenated `param` with a `{0}` placeholder and pass the user input via the parameterized `filterArgs` array. JNDI's `DirContext.search()` automatically escapes string-valued arguments per RFC 4515, preventing LDAP metacharacter injection.

## Explanation

The `DirContext.search(String name, String filter, Object[] filterArgs, SearchControls cons)` method provides built-in protection against LDAP injection by separating filter structure from user data. String arguments in the `filterArgs` array are automatically escaped by JNDI's service provider, neutralizing special LDAP characters (`*`, `(`, `)`, `\`, NUL). By replacing string concatenation with placeholders (`{0}`, `{1}`, etc.) and supplying untrusted values through the parameterized array instead, the filter structure remains under application control and user input is treated as data, not query syntax.

## Behaviour changes

- Filter now uses parameterized substitution instead of string concatenation
- The escaped value of `param` is substituted into the filter at evaluation time by JNDI
- Query logic and results remain identical for valid input; injection attempts are neutralized
- No change to method signature, return type, or error handling
