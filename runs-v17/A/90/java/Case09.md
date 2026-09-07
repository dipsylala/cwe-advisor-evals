## Verdict
Confirmed. The case exhibits CWE-90 (LDAP Injection) at line 32 of Case09E.java. Untrusted data from the HTTP request parameter flows through the call chain (Case09A → Case09B → Case09C → Case09D → Case09E) and is concatenated directly into an LDAP filter string without sanitization. An attacker can inject LDAP filter metacharacters to alter the search logic.

## Source
**File:** Case09E.java  
**Line:** 32  
**Sink:** `directoryContext.search("", search, null)`

The vulnerable code constructs an LDAP filter by concatenating untrusted `data`:
```
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

An input like `*)(cn=*` would break out of the intended filter and match all entries.

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
            
            String search = "(cn=" + escapeLdapFilter(data) + ")";

            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
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

    private static String escapeLdapFilter(String input) {
        if (input == null) {
            return null;
        }
        
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\\':
                    sb.append("\\5c");
                    break;
                case '\0':
                    sb.append("\\00");
                    break;
                case '/':
                    sb.append("\\2f");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}
```

## Explanation
The fix escapes LDAP filter metacharacters before constructing the search filter. LDAP filters use special characters (`*`, `(`, `)`, `\`, null, `/`) with syntactic meaning. By converting these to their hex escape sequences (e.g., `*` → `\2a`, `(` → `\28`, `)` → `\29`), the input is treated as literal data and cannot alter the filter structure.

The `escapeLdapFilter()` method iterates over each character in the user-supplied input and replaces metacharacters with their escaped equivalents. The escaped string is then safe to concatenate into the LDAP filter expression. This prevents injection attacks where an attacker could use characters like `*` or parentheses to modify the query logic.

Only Case09E.java requires modification since it contains the sink (the LDAP search call). Cases A through D are pass-through layers that do not perform any operations on the data, so they remain unchanged.
