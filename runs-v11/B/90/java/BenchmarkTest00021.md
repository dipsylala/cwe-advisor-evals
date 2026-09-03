## Verdict

CONFIRMED: LDAP Injection via filter string concatenation. Untrusted request parameter is concatenated directly into an LDAP filter string passed to `DirContext.search()`, allowing attackers to inject LDAP filter syntax and manipulate directory queries.

## Source

Line 44: User-controlled parameter obtained from HTTP request.
```java
String param = request.getParameter("BenchmarkTest00021");
```

Line 54: Parameter concatenated into LDAP filter string without escaping.
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
```

## Fix

Replace string concatenation with parameterized placeholders. Use `{0}` and `{1}` as placeholders for user-controlled values and pass the actual values through the `filterArgs` array parameter to `DirContext.search()`.

**Lines 54-55 (original):**
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
```

**Lines 54-55 (fixed):**
```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
```

## Explanation

JNDI's `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload automatically escapes string-valued filter arguments according to RFC 4515 before the filter is transmitted to the LDAP server. This prevents special characters like `*`, `(`, `)`, `\`, and NUL from being interpreted as filter syntax.

The fix moves the untrusted `param` from being concatenated into the filter string to being passed as the first filter argument. JNDI will escape it, eliminating the injection point. The hardcoded directory value moves to a second placeholder. Both values are now passed through the safe parameterized mechanism.

## Behaviour changes

No functional behaviour changes. The search still returns the same results, iterates through the same `NamingEnumeration`, and produces identical output. The `SearchControls` configuration remains unchanged. Error handling and exception propagation are unaffected. Only the mechanism for delivering user input to the filter is changed—from unsafe concatenation to safe parameterization.
