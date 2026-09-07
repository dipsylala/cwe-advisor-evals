## Verdict
Exploitable. The untrusted input parameter `data` is concatenated directly into an LDAP filter string on line 29 without any escaping, then passed to `DirContext.search()` on line 32. An attacker controlling the `data` parameter can inject LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to modify the query structure and escape the intended filter clause.

## Source
Case17A.java line 18 calls Case17B.handleSink() with a data parameter. Case17B receives this input and uses it directly in filter construction without validation or escaping.

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

            // Fixed: Use parameterized search with filterArgs to prevent LDAP injection
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new String[]{data}, new SearchControls());
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
The vulnerability was eliminated by switching from string concatenation to JNDI's parameterized `DirContext.search()` overload. The original code built the filter dynamically by concatenating user input directly: `String search = "(cn=" + data + ")"`. This allowed an attacker to inject LDAP filter syntax.

The fixed code uses a placeholder syntax `(cn={0})` and passes the user input separately via the `filterArgs` parameter as `new String[]{data}`. JNDI automatically applies RFC 4515 escaping to each element in the `filterArgs` array, converting special LDAP metacharacters to their safe escaped forms. The `SearchControls()` parameter specifies the search controls; the default scope and return attributes are appropriate here. This approach separates query structure from data, preventing injection regardless of the input content.

## Behaviour changes
No functional behaviour changes. The search still filters by `cn` attribute with the provided data value, and all results are processed identically. The only difference is that special LDAP characters in `data` are now properly escaped by JNDI's RFC 4515 escaper, preventing syntax injection while preserving legitimate searches. Payloads like `*`, `*)`, or `*)(uid=*)` are now treated as literal string values to match rather than LDAP filter operators.
