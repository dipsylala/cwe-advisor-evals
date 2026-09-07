## Verdict
True Positive

## Source
Line 60 builds an LDAP filter by concatenating user-controlled `param` directly into the filter string:
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
```

The `param` is sourced from the request header at line 45 and URL-decoded at line 52 without sanitization. An attacker can inject LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to alter the query logic and bypass authentication or authorization checks.

## Fix
Use parameterized filter placeholders instead of string concatenation. Replace the filter string and Object array:

**Before:**
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
```

**After:**
```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
```

The LDAP search method automatically escapes parameters passed in the Object array, preventing injection of filter metacharacters.

## Explanation
LDAP injection occurs when user input is concatenated into a filter string without escaping LDAP metacharacters. The `InitialDirContext.search()` method accepts parameterized filters via positional placeholders (`{0}`, `{1}`, etc.) paired with an Object array. When parameters are passed this way, the LDAP provider automatically escapes special characters, preventing filter syntax injection. By moving `param` from string concatenation to the parameterized filter position `{0}`, the fix ensures that any LDAP metacharacters in the user input are rendered literal and harmless.
