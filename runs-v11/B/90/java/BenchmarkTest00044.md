## Verdict

**CWE-90: LDAP Injection**

**File:** evals/cases/90/java/BenchmarkTest00044/BenchmarkTest00044.java  
**Line:** 60 (sink)  
**Status:** Exploitable  
**Confidence:** High

The vulnerability is confirmed: untrusted user input flows directly into an LDAP filter without escaping, allowing injection of LDAP metacharacters.

## Source

**Source:** `request.getParameterValues("BenchmarkTest00044")` at line 44  
**Sink:** `ctx.search(base, filter, sc)` at line 60

**Data Flow:**
1. User input extracted from HTTP request parameter (line 44)
2. Assigned to `param` variable (line 46)
3. Concatenated directly into LDAP filter string without escaping (line 56)
4. Filter passed to JNDI search operation (line 60)

An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to modify the query logic—for example, changing a single-user lookup into an unrestricted search by injecting `*)(objectClass=*))(|(uid=*`.

## Fix

**Vulnerable code:**
```java
String filter = "(&(objectclass=person)(uid=" + param + "))";
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        // SAST FINDING: CWE-90 (LDAP Injection) - an LDAP filter is built from request data and searched. Sink is the next statement.
        ctx.search(base, filter, sc);
```

**Fixed code:**
```java
String filter = "(&(objectclass=person)(uid={0}))";
Object[] filterArgs = new Object[]{param};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, filterArgs, sc);
```

## Explanation

The fix replaces string concatenation with JNDI's parameterized search overload, which accepts user input through a separate `filterArgs` parameter. JNDI automatically escapes each argument according to RFC 4515, neutralizing LDAP metacharacters and preventing injection. The filter string now uses a `{0}` placeholder for the first argument, making the query structure explicit and separate from untrusted data. The additional `searchControls` argument (required when using `filterArgs`) is already present in the original code, so the call signature changes from 3 to 4 arguments with no other side effects.

## Behaviour changes

- **Call signature change:** `ctx.search(base, filter, sc)` → `ctx.search(base, filter, filterArgs, sc)`. The parameterized overload requires a 4-argument call with `SearchControls` as the trailing parameter; the original `SearchControls` object is preserved.
- **Automatic escaping:** JNDI applies RFC 4515 escaping to `filterArgs[0]` at the point of the search, so special characters in `param` are neutralized without manual intervention.
- **No functional regression:** The search scope (`SUBTREE_SCOPE`), base DN, and result handling remain identical. The query now correctly restricts results to a single user instead of allowing wildcard expansion.
