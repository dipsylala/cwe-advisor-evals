## Verdict
exploitable

## Source
Line 16 in Case07A.java: `data = request.getParameter("name")` — untrusted HTTP request parameter passed through call chain to LDAP filter construction at line 32 of Case07B.java.

## Fix

### File: Case07B.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import javax.naming.*;
import javax.naming.directory.*;

import java.util.Hashtable;
import java.util.logging.Level;

public class Case07B
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
The original code constructs an LDAP search filter by string concatenation: `"(cn=" + data + ")"`, allowing attackers to inject LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to modify the query logic. The fix replaces string concatenation with JNDI's parameterized `DirContext.search()` overload. The filter template uses `{0}` as a placeholder, and the untrusted data is passed separately via the `filterArgs` array. JNDI automatically escapes each argument per RFC 4515 before substitution, preventing injection attacks. The `new SearchControls()` provides the required fourth parameter with default search settings. This approach keeps structure separate from data and eliminates the injection point.

## Behaviour changes
Added `Object[] filterArgs = { data };` to hold the parameterized argument. Changed `directoryContext.search("", search, null)` (3 arguments) to `directoryContext.search("", search, filterArgs, new SearchControls())` (4 arguments) to use the parameterized overload. The `SearchControls()` parameter was not present in the original call, now required by the parameterized API — it uses default settings (SUBTREE scope, no attribute filter, no count/time limits) which preserves the original search semantics.
