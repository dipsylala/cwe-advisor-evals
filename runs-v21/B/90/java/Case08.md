## Verdict

Exploitable. Untrusted user input from `request.getParameter("name")` flows through the call chain (Case08A → Case08B → Case08C → Case08D) and is concatenated directly into an LDAP search filter without escaping or parameterization, allowing injection of LDAP filter syntax.

## Source

`request.getParameter("name")` in Case08A.handle() (line 16).

Untrusted parameter is passed through the call chain:
- Case08A.handle() → Case08B.handleSink()
- Case08B.handleSink() → Case08C.handleSink()
- Case08C.handleSink() → Case08D.handleSink()

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
            String[] filterArgs = {data};
            SearchControls searchControls = new SearchControls();

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, searchControls);
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

The fix replaces string concatenation with JNDI's parameterized filter API. Line 29 changed from `"(cn=" + data + ")"` to a template `"(cn={0})"`, and line 32 now uses the four-argument `search(String, String, Object[], SearchControls)` overload that accepts separate filter arguments. The untrusted data is passed via the `filterArgs` array (a new line 30), where JNDI's LDAP provider escapes it per RFC 4515 before the filter is sent to the directory server. This prevents injection of LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) that would otherwise break the filter structure. `SearchControls` (line 31) is required by this overload; the default constructor provides standard scope and attribute handling.

## Behaviour changes

The search behavior is identical: the filter still matches entries where `cn` equals the user-supplied value, but now that value is properly escaped and cannot close the filter term or inject new clauses. No attributes are lost, return values are unchanged, and error handling is unaffected.
