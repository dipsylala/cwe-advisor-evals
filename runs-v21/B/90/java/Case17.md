## Verdict

CONFIRMED. LDAP Injection in Case17B.java at line 32. The filter string is constructed by concatenating untrusted input `data` into an LDAP filter without escaping. An attacker can inject LDAP metacharacters (`*`, `(`, `)`) to bypass authentication or modify query logic.

## Source

Parameter `data` in `Case17B.handleSink(String data, ...)` originates from Case17A.java and reaches the LDAP search filter construction at line 31.

## Fix

### File: Case17B.java

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import javax.naming.*;
import javax.naming.directory.*;

import java.util.Hashtable;
import java.util.logging.Level;

public class Case17B
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
            String[] filterArgs = {data};
            SearchControls controls = new SearchControls();

            // SAST FINDING: CWE-90 (LDAP Injection) - FIXED: Use parameterized filter with filterArgs to escape input automatically per RFC 4515
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, controls);
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

The fix replaces string concatenation with JNDI's parameterized search filter mechanism. Instead of `"(cn=" + data + ")"`, the filter uses a placeholder `{0}` and passes the value through the `filterArgs` parameter. JNDI's `DirContext.search()` method automatically escapes the `filterArgs` values according to RFC 4515, neutralizing LDAP metacharacters like `*`, `(`, and `)`. A `SearchControls` object (with default settings) is required as the fourth argument when using `filterArgs`. This approach separates query structure from user data, preventing injection attacks.

## Behaviour changes

None. The search operation returns identical results. The parametrized API preserves all existing functionality while applying automatic escaping to the input value.
