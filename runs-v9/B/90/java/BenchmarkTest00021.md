## Verdict

Exploitable.

## Source

`request.getParameter("BenchmarkTest00021")` (line 44), assigned to `param` (defaulted to `""` if absent). This is attacker-controlled HTTP request data with no validation or encoding applied before use.

## Fix

Vulnerable code:

```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        // SAST FINDING: CWE-90 (LDAP Injection) - an LDAP filter is built from request data and searched. Sink is the next statement.
        ctx.search(base, filter, filters, sc);
```

Fixed code:

```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, filters, sc);
```

## Explanation

The `filter` string previously concatenated `param` directly into the `uid=` clause, so a value such as `*)(uid=*` closes that term and reopens a new one, letting an attacker rewrite the search's boolean structure. The fix replaces the concatenation with a second `{1}`-style placeholder (`{0}` was already reserved for the `street` value) and passes `param` through JNDI's own `filterArgs` array on the existing `ctx.search(base, filter, filters, sc)` overload. Because `param` is passed as a `String`, JNDI escapes it per RFC 2254/4515 before it reaches the filter, so metacharacters such as `*`, `(`, `)`, and `\` are neutralized rather than interpreted as filter syntax. The sink call itself, its argument count, and the `SearchControls` argument are all unchanged, so the fix stays entirely within the value-substitution mechanism the API already provides.

## Behaviour changes

None. The sink is still `ctx.search(base, filter, filters, sc)` with the same base DN, search scope, and result handling; the only change is that `uid` is now supplied via `filterArgs` instead of string concatenation, and JNDI's escaping only affects how special characters are matched literally rather than what the code returns to the caller on the non-malicious path.
