## Verdict

CONFIRMED. The LDAP filter is constructed by concatenating untrusted data without escaping special LDAP metacharacters. An attacker controlling the `data` parameter could inject characters like `)`, `(`, or `*` to modify the query structure and bypass authentication or access unauthorized directory entries.

## Source

**Case17A.java line 16-18:** Data is passed to Case17B.handleSink() where it enters the LDAP search chain.

**Case17B.java line 29:** The filter string is constructed by string concatenation:
```
String search = "(cn=" + data + ")";
```

**Case17B.java line 32:** The concatenated filter is passed directly to `directoryContext.search()`:
```
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

The call uses the three-argument `search(String name, String filterExpr, SearchControls cons)` overload, which treats the filter expression as a literal string. JNDI does not escape the filter string in this overload.

## Fix

Use JNDI's parameterized `search()` overload that accepts filter arguments separately. This overload applies RFC 4515 escaping to each argument automatically.

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

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[]{data}, new SearchControls());
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

The fix replaces string concatenation with parameterized placeholders. Line 29 now uses `{0}` as a placeholder instead of concatenating the data directly. Line 32 calls the four-argument `search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload, passing the user data via the `filterArgs` parameter and providing a default `SearchControls()` object. JNDI automatically escapes each argument in the filter array per RFC 4515, which neutralizes all LDAP metacharacters (`*`, `(`, `)`, `\`, NUL). This prevents the attacker from breaking out of the filter term or injecting new clauses.

## Behaviour changes

The behavioural contract of the search is preserved:
- **Returns:** Still returns a `NamingEnumeration<SearchResult>` that the caller iterates through
- **Scope:** The search base (`""`) and filter structure remain unchanged; only the data escaping differs
- **Exception handling:** Still throws `NamingException` on LDAP errors, caught and logged as before
- **Scope controls:** The default `SearchControls()` applies reasonable defaults (SUBTREE scope, standard timeout)

The only visible change is that LDAP-unsafe characters in the data are now escaped, causing them to match literally in the directory rather than being interpreted as LDAP syntax. For legitimate data (usernames, attribute values without LDAP metacharacters), the results are identical.
