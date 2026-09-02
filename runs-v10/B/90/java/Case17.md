## Verdict

LDAP Injection (CWE-90) confirmed. User input from the `data` parameter is concatenated into an LDAP search filter at line 29 and passed unsanitized to `DirContext.search()` at line 32, allowing attackers to inject metacharacters (`*`, `(`, `)`, `\`) to manipulate the query and access unauthorized directory data.

## Source

**File:** Case17B.java, lines 29 and 32

**Call chain:** `data` parameter → concatenated into filter string `(cn=" + data + ")"` → passed to `directoryContext.search("", search, null)`

**Attacker control:** The `data` parameter flows from the HTTP request through Case17A (line 18), making it attacker-controllable in a real application. Test case provides `"foo"`, but production code would receive unsanitized user input.

## Fix

Replace the concatenated LDAP filter string with a parameterized filter using JNDI's parameterized `search()` overload, which automatically escapes filter arguments per RFC 4515.

**Vulnerable code:**
```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[]{data}, new SearchControls());
```

## Explanation

The fix uses JNDI's parameterized `search(name, filterExpr, filterArgs, cons)` overload, which separates filter structure from user data. Each element in the `filterArgs` array is automatically escaped per RFC 4515, neutralizing LDAP metacharacters. The `{0}` placeholder is replaced with the escaped value of `data` at line 29. 

This overload requires a trailing `SearchControls` parameter; `new SearchControls()` supplies the default scope (SUBTREE). The original call passed `null` for controls, which internally defaults to SUBTREE scope, so the behavior is preserved.

Escaping is applied at JNDI's level before the filter leaves the JVM, removing the injection point entirely. No configuration or additional libraries are required beyond what Case17B already imports.

## Behaviour changes

- **Input handling:** `data` is now escaped per RFC 4515 within JNDI's `search()` method, removing attacker control over filter syntax.
- **Search behavior:** Search scope, attributes, and return behavior are unchanged (default SUBTREE scope applied via default `SearchControls()`).
- **Error handling:** No change. `NamingException` handling remains the same.
- **Performance:** Negligible impact. Parameterized queries incur one escaping pass per invocation, already required by RFC 4515 compliance.
- **Compatibility:** No compatibility impact. This is a standard JNDI pattern supported since Java 1.3+.
