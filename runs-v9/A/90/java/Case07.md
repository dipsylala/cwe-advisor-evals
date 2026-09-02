## Verdict
Confirmed. LDAP injection.

## Source
`Case07A.handle()` reads the untrusted HTTP parameter:

```java
data = request.getParameter("name");
```

and passes it unmodified into `Case07B.handleSink(data, request, response)`.

## Fix

```java
public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    Hashtable<String, String> environmentHashTable = new Hashtable<String, String>();
    environmentHashTable.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    environmentHashTable.put(Context.PROVIDER_URL, "ldap://localhost:389");
    DirContext directoryContext = null;

    try
    {
        directoryContext = new InitialDirContext(environmentHashTable);

        String search = "(cn={0})";

        // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
        NamingEnumeration<SearchResult> answer =
            directoryContext.search("", search, new Object[] { data }, new SearchControls());
        while (answer.hasMore())
        {
            SearchResult searchResult = answer.next();
            Attributes attributes = searchResult.getAttributes();
            NamingEnumeration<?> allAttributes = attributes.getAll();
            while (allAttributes.hasMore())
            {
                Attribute attribute = (Attribute) allAttributes.next();
                NamingEnumeration<?> allValues = attribute.getAll();
                while (allValues.hasMore())
                {
                    IO.writeLine(" Value: " + allValues.next().toString());
                }
            }
        }
    }
    catch (NamingException exceptNaming)
    {
        IO.logger.log(Level.WARNING, "The LDAP service was not found or login failed.", exceptNaming);
    }
    finally
    {
        if (directoryContext != null)
        {
            try
            {
                directoryContext.close();
            }
            catch (NamingException exceptNaming)
            {
                IO.logger.log(Level.WARNING, "Error closing DirContext", exceptNaming);
            }
        }
    }
}
```

## Explanation
The original code built the LDAP search filter by string concatenation: `"(cn=" + data + ")"`. Because `data` comes directly from `request.getParameter("name")` with no validation or escaping, an attacker can inject LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to alter the filter's logical structure - for example supplying `*)(uid=*))(|(uid=*` to widen the search to all entries, or to break out of the intended attribute comparison entirely and inject arbitrary filter clauses. This is directly analogous to SQL injection but against the LDAP query language, and can lead to unauthorized data disclosure, authentication bypass in directory-backed login flows, or denial of service against the directory server.

The fix replaces manual string concatenation with the parameterized `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload. The filter expression uses a `{0}` placeholder, and the untrusted value is passed separately in the `filterArgs` array. The JNDI LDAP provider substitutes the argument into the filter after applying RFC 4515-compliant escaping of the LDAP special characters (`*`, `(`, `)`, `\`, NUL), so the value can never change the structure of the query regardless of its content - the same separation-of-code-and-data principle as a parameterized SQL query. This is the standard, Oracle-documented mechanism for building dynamic LDAP filters safely and requires no hand-rolled escaping logic that could be incomplete or later drift out of sync with the LDAP filter grammar.

An explicit `SearchControls()` is passed instead of `null` because the `filterArgs` overload does not have a `null`-controls variant; a default-constructed `SearchControls` preserves the original search behavior (single-level default scope).
