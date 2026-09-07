## Verdict
CONFIRMED. The code constructs an LDAP filter by concatenating untrusted user input directly into the search string at line 29, then passes it to `directoryContext.search()` at line 32. An attacker can inject LDAP filter syntax (e.g., `*`, `(`, `)`) to alter the query logic.

## Source
**File**: Case07B.java  
**Lines**: 29, 32  
**Call chain**: Case07A.handle() → Case07B.handleSink() → directoryContext.search()

The vulnerability originates when Case07A retrieves the untrusted `name` parameter from the HTTP request at line 16 and passes it to Case07B.handleSink() as the `data` parameter. Case07B then uses this data in line 29 to build an LDAP filter string via concatenation, and executes the filter against the LDAP directory at line 32 without any sanitization.

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
    private static String escapeLdapFilterSpecialChars(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\0':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }

    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        Hashtable<String, String> environmentHashTable = new Hashtable<String, String>();
        environmentHashTable.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        environmentHashTable.put(Context.PROVIDER_URL, "ldap://localhost:389");
        DirContext directoryContext = null;

        try
        {
            directoryContext = new InitialDirContext(environmentHashTable);
            
            String search = "(cn=" + escapeLdapFilterSpecialChars(data) + ")";

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
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
}
```

## Explanation
LDAP filters use special characters (`*`, `(`, `)`, `\`) with syntactic meaning. When user input is concatenated directly into a filter string, these characters allow an attacker to alter the filter's logic. For example, injecting `*)(|(uid=*` transforms the filter from `(cn=*)(|(uid=*)` to `(cn=*)(|(uid=*)`, changing the query to return unintended results.

The fix escapes LDAP filter special characters in the user-supplied input before building the filter. The `escapeLdapFilterSpecialChars()` method replaces each dangerous character with its hexadecimal escape sequence (e.g., `*` becomes `\2a`, `(` becomes `\28`) following RFC 4515 conventions. This ensures that any user input is treated as literal data, not as LDAP filter syntax.

After escaping, `data` is safe to concatenate into the filter string, and the LDAP search at line 32 operates on the literal user input without risk of injection attacks.
