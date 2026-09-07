## Verdict

Exploitable. The untrusted HTTP parameter flows through the call chain (Case08A → Case08B → Case08C → Case08D) directly into an LDAP filter string via concatenation, and the concatenated filter is passed to `DirContext.search()` without parameterization or escaping. An attacker can inject LDAP filter metacharacters to modify query logic.

## Source

`HttpServletRequest.getParameter("name")` in Case08A (line 16), attacker-controlled HTTP request parameter, passed through Case08B, Case08C to Case08D.

## Fix

### File: Case08D.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import javax.naming.*;
import javax.naming.directory.*;

import java.util.Hashtable;
import java.util.logging.Level;

public class Case08D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        Hashtable<String, String> environmentHashTable = new Hashtable<String, String>();
        environmentHashTable.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        environmentHashTable.put(Context.PROVIDER_URL, "ldap://localhost:389");
        DirContext directoryContext = null;

        try
        {
            directoryContext = new InitialDirContext(environmentHashTable);
            
            String search = "(cn={0})";

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            Object[] filterArgs = { data };
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, new SearchControls());
            while (answer.hasMore())
            {
                SearchResult searchResult = answer.next();
                Attributes attributes = searchResult.getAttributes();
                NamingEnumeration<?> allAttributes = attributes.getAll();
                while (allAttributes.hasMore())
                {
                    Attribute attribute = (Attribute) allAttributes.next();
                    NamingEnumeration<?> allValues = attribute.getAll();
                    while(allValues.hasMore())
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
}
```

## Explanation

The vulnerability is eliminated by using JNDI's built-in parameterized search filter API. Instead of concatenating untrusted data directly into the filter string, the filter now uses a `{0}` placeholder and passes the user-supplied value via the `filterArgs` Object array parameter. The JNDI provider (LdapCtxFactory) automatically escapes the filter argument according to RFC 4515, preventing LDAP metacharacters from being interpreted as filter syntax. This approach separates query structure from data, ensuring that values like `*`, `)`, and `(` are treated as literal string content rather than filter operators.

## Behaviour changes

Two behaviour changes from the original:

1. **SearchControls parameter**: The call now passes `new SearchControls()` instead of `null` for the fourth parameter. This supplies default search controls (SUBTREE scope, unlimited size limit and time limit, no specific attributes to return). The original `null` also used defaults, so the functional behaviour is identical - this is a required parameter when using the parameterized `filterArgs` overload.

2. **Automatic LDAP escaping**: The JNDI provider now applies RFC 4515 escaping to the `data` parameter before constructing the filter. Special characters like `*`, `(`, `)`, `\`, and NUL are escaped, preventing injection. This transforms attacker-supplied payloads into literal filter values instead of filter operators, but does not change the query's legitimate results - a search for user input `cn=admin*` now correctly returns entries with `cn` equal to the literal string `admin*` rather than all entries starting with `admin`.
