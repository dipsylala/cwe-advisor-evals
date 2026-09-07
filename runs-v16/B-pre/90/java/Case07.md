## Verdict

Exploitable. Untrusted user input from an HTTP request parameter flows directly into an LDAP search filter via string concatenation, allowing an attacker to inject LDAP query syntax.

## Source

**Case07A.java, line 16:**
```java
data = request.getParameter("name");
```

**Case07B.java, line 29:**
```java
String search = "(cn=" + data + ")";
```

The `data` parameter originates from an untrusted HTTP request and is concatenated directly into the LDAP filter string without escaping.

## Fix

**Vulnerable code (Case07B.java, lines 29-32):**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String filterTemplate = "(cn={0})";

NamingEnumeration<SearchResult> answer = directoryContext.search("", filterTemplate, new String[]{data}, new SearchControls());
```

## Explanation

The vulnerability occurs because user-supplied data is concatenated into an LDAP filter string, allowing an attacker to inject metacharacters like `*`, `(`, `)`, or `\` to modify the query logic. The fix uses JNDI's parameterized `DirContext.search(name, filterExpr, filterArgs, cons)` overload, which separates filter structure from data. The filter template uses `{0}` as a placeholder for the user-supplied value, which is passed separately via the `filterArgs` parameter as a String. JNDI automatically applies RFC 4515 escaping to string-valued arguments, neutralizing all LDAP metacharacters before the query reaches the directory server. The `new SearchControls()` argument provides default search behavior and is required when using the filterArgs overload.

## Behaviour changes

- Filter string changed from string concatenation to parameterized template with placeholder `(cn={0})`
- Added `filterArgs` parameter containing `new String[]{data}` to pass user input separately from filter structure
- Replaced `null` SearchControls argument with `new SearchControls()` to satisfy the parameterized overload signature requirement; this maintains default search scope and timeout behavior equivalent to the original call

No change in query semantics, return type, or result handling. The search continues over the same base DN and returns SearchResult objects processed identically to the original code.
