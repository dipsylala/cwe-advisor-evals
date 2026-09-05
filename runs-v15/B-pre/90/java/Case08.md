## Verdict

**Exploitable**

CWE-90 (LDAP Injection) confirmed. The untrusted `data` parameter is concatenated directly into an LDAP filter string without escaping, allowing attackers to inject LDAP filter syntax (e.g., `*`, `()`) to modify query logic and access unauthorized directory entries.

## Source

**File:** `evals/cases/90/java/Case08/Case08D.java`  
**Lines:** 17–32  
**Data flow:**
- Line 17: `data` parameter received from HTTP request (untrusted)
- Line 29: String concatenation `"(cn=" + data + ")"` - no escaping applied
- Line 32: Sink - `directoryContext.search("", search, null)` - untrusted filter passed to JNDI search

## Fix

**Vulnerable code (line 29–32):**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
SearchControls cons = new SearchControls();
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new String[]{data}, cons);

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new String[]{data}, cons);
```

## Explanation

The fix uses JNDI's parameterized `DirContext.search()` overload, which applies RFC 4515 escaping to filter arguments automatically. By replacing the concatenated filter string with a placeholder `{0}` and passing the user input via the `filterArgs` parameter as a `String` array, the JNDI framework guarantees that special characters (`*`, `(`, `)`, `\`, NUL) are properly escaped before the filter is parsed. This prevents an attacker from injecting LDAP syntax to modify the query structure. The trailing `SearchControls` parameter is required by the parameterized overload and establishes the default search scope.

## Behaviour changes

**Change:** Fourth parameter added to `search()` call - `new SearchControls()` supplied where the original passed `null` for `SearchControls`.

**Reason:** The parameterized overload signature is `search(Name, String, Object[], SearchControls)`. The original three-argument call passed `null` for `SearchControls`, which relied on a different (vulnerable) overload. The four-argument parameterized overload requires an explicit `SearchControls` object; `new SearchControls()` supplies the default search scope (the search base and its immediate children), matching typical usage. The developer should verify this scope is appropriate for their use case—if a different scope was originally intended, it should be set on the `SearchControls` object (e.g., `cons.setSearchScope(SearchControls.SUBTREE_SCOPE)` for recursive search).

**Change:** Filter string format changed from concatenated to parameterized.

**Reason:** Switches from unsafe string concatenation to safe parameterized filtering, which is the primary defence mechanism for this vulnerability in JNDI.
