## Verdict

Exploitable. Untrusted data from an HTTP header flows through URL decoding directly into an LDAP filter via string concatenation at line 60, then reaches the LDAP search sink at line 69 without escaping. An attacker can inject LDAP filter metacharacters to alter query logic.

## Source

**Input source (line 45-48):** HTTP header `BenchmarkTest00012` read via `request.getHeaders()`, URL decoded at line 52.

**Taint path:** 
1. Line 45-48: `param = headers.nextElement()` - untrusted HTTP header
2. Line 52: `param = java.net.URLDecoder.decode(param, "UTF-8")` - decoded but still untrusted
3. Line 60: `String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))"` - concatenated into filter
4. Line 69: `idc.search(base, filter, filters, sc)` - filter used in LDAP search

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

## Explanation

The vulnerability occurs because `param` is concatenated into the LDAP filter string at line 60, bypassing JNDI's built-in RFC 4515 escaping. An attacker can inject filter metacharacters like `*`, `)`, and `(` to break the filter syntax and execute arbitrary queries.

The fix replaces string concatenation with a placeholder (`{0}`) and passes the user-supplied value through JNDI's `DirContext.search()` `filterArgs` parameter. JNDI automatically escapes all special characters in filterArgs according to RFC 4515, neutralizing metacharacters like `*`, `\`, `(`, `)`, and NUL. This separates filter structure from user data, making injection impossible.

The second filter argument placeholder changes from `{0}` to `{1}` to accommodate the new first argument, maintaining the original value for the street attribute.

## Behaviour changes

**Arguments supplied to DirContext.search():** The `filterArgs` array now contains two elements instead of one, with `param` inserted as the first argument. JNDI will escape both values using RFC 4515 before substituting them into the filter placeholders.

**Filter structure:** The filter string no longer uses string concatenation for the uid value; it now uses `{0}` placeholder syntax that JNDI processes safely.

**No other changes:** Return value remains `NamingEnumeration<SearchResult>`, search scope and base DN are unchanged, exception handling is preserved.
