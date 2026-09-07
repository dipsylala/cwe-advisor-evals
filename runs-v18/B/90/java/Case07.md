## Verdict
CONFIRMED. The vulnerability is exploitable. Untrusted data from `request.getParameter("name")` is directly concatenated into an LDAP filter without escaping or validation.

## Source
Line 16 of Case07A.java: `data = request.getParameter("name");` - attacker-controlled HTTP request parameter.

Flow: Case07A.java line 16 → Case07A.java line 18 (passed to Case07B) → Case07B.java line 29 (concatenated into filter) → Case07B.java line 32 (sent to LDAP server without escaping).

## Fix
Replace the concatenated filter with JNDI's parameterized `search()` overload that separates filter structure from user data.

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
            
            String filterExpr = "(cn={0})";
            Object[] filterArgs = {data};

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", filterExpr, filterArgs, new SearchControls());
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
The fix replaces string concatenation of the LDAP filter with JNDI's parameterized `search()` overload. Instead of building `"(cn=" + data + ")"`, the fixed code uses a filter expression `"(cn={0})"` with placeholder, and passes the untrusted `data` as a separate String argument in the `filterArgs` array. The JNDI provider automatically applies RFC 4515 escaping to each argument, preventing LDAP metacharacters like `*`, `(`, `)`, `\`, and NUL from modifying query structure. The fourth argument `new SearchControls()` provides default search parameters as required by this overload signature. This approach separates filter structure from data, making injection impossible.

## Behaviour changes
- Added `filterExpr` variable holding the static filter template `"(cn={0})"`
- Added `filterArgs` array containing the untrusted `data` as a single String element
- Changed `directoryContext.search()` call from the non-parameterized three-argument overload `search(String, String, SearchControls)` to the parameterized four-argument overload `search(String, String, Object[], SearchControls)`, passing filter expression and arguments separately
- LDAP queries now safely handle special characters in `data` (e.g., `admin*` or `*)(uid=*`) by escaping them rather than interpreting them as filter syntax
