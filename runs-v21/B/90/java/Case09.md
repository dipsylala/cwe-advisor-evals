## Verdict
exploitable

## Source
Case09A.java line 16: `data = request.getParameter("name")` - untrusted HTTP request parameter flows through the call chain (Case09B → Case09C → Case09D) to Case09E.

## Fix

### File: Case09E.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import javax.naming.*;
import javax.naming.directory.*;

import java.util.Hashtable;
import java.util.logging.Level;

public class Case09E
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
            
            String filterExpr = "(cn={0})";

            // Fixed: Use parameterized search with filterArgs to prevent LDAP injection
            NamingEnumeration<SearchResult> answer = directoryContext.search("", filterExpr, new Object[]{data}, new SearchControls());
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

The vulnerability existed because untrusted user input from the HTTP request parameter was concatenated directly into an LDAP filter string at line 29 (`String search = "(cn=" + data + ")"`), and then passed to `directoryContext.search()` at line 32. This allows attackers to inject LDAP filter syntax—for example, providing `*` as input results in the filter `(cn=*)` which matches any entry, or providing `*)(|(cn=*` to break out of the current clause and manipulate the query logic.

The fix replaces string concatenation with JNDI's parameterized `search()` API, which applies RFC 4515 escaping automatically. The filter expression `(cn={0})` uses a placeholder for the user-supplied value, which is passed separately through the `filterArgs` parameter as `new Object[]{data}`. JNDI's implementation escapes metacharacters in the placeholder positions, preventing the injection. The fourth parameter is changed from `null` to `new SearchControls()` to provide the required `SearchControls` argument that the parameterized overload requires.

## Behaviour changes

1. **SearchControls parameter**: The original call passed `null` as the third parameter to `directoryContext.search()`, which was for SearchControls. The fixed version explicitly passes `new SearchControls()` to provide default search control settings. This is required by the parameterized `search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload. The default SearchControls behavior is unchanged from the `null` default in the original implementation.

2. **Filter structure**: The filter is no longer built by string concatenation but is expressed as a parameterized template with placeholders. The actual filter sent to the LDAP server remains structurally identical for valid inputs, but injection payloads are neutralized by escaping.
