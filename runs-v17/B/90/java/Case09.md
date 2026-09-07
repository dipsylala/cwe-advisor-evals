## Verdict

CONFIRMED. The vulnerability is a direct LDAP injection through unsanitized string concatenation into an LDAP filter expression passed to JNDI's `DirContext.search()`.

## Source

Untrusted user input originates from `HttpServletRequest.getParameter("name")` in Case09A (line 16) and flows through the call chain Case09A → Case09B → Case09C → Case09D → Case09E without validation or escaping.

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

The vulnerability was on line 29-32 of the original code. The data parameter was concatenated directly into the LDAP filter string `"(cn=" + data + ")"`, allowing an attacker to inject LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to manipulate the directory query. For example, supplying `*` would create the filter `(cn=*)`, matching all entries, and more complex payloads could exploit the LDAP filter syntax to access unauthorized directory information.

The fix replaces string concatenation with JNDI's native parameterized API. The filter string now uses the `{0}` placeholder (`"(cn={0})"`), and the user-controlled data is passed separately via the `filterArgs` parameter as `new Object[]{data}`. JNDI automatically escapes each argument according to RFC 4515 (LDAP filter encoding), ensuring that metacharacters are neutralized before the query is sent to the directory service. The fourth parameter `new SearchControls()` is required because the parameterized overload mandates a SearchControls argument; the default settings are appropriate here.

No other code changes are needed because the rest of the method's logic (iterating through results, accessing attributes) remains compatible with the parameterized API.

## Behaviour changes

The parameterized API produces identical search results for legitimate input while blocking injection attacks. Special characters in the user input are escaped and treated as literal values, not as LDAP syntax. For example:
- Input `alice` → filter becomes `(cn=alice)` - unchanged behaviour
- Input `*` → filter becomes `(cn=\2a)` (escaped) - now returns no match instead of matching all entries
- Input `*)(objectClass=*))(&(cn=*` → characters are escaped to prevent injection - now returns no match instead of potentially fragmenting the query

The method signature change from `search(name, filter, SearchControls)` to `search(name, filter, filterArgs, SearchControls)` is an API contract of JNDI and poses no compatibility risk because the return type and method name remain identical.
