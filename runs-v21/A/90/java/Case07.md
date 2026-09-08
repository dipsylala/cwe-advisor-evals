## Verdict
Confirmed LDAP injection vulnerability. Untrusted input from HTTP request parameter is concatenated directly into an LDAP filter string without escaping, allowing an attacker to inject LDAP metacharacters and modify the query logic.

## Source
The vulnerability exists in the call chain:
- **Case07A.java, line 16**: `data = request.getParameter("name")` retrieves untrusted user input
- **Case07A.java, line 18**: Passes untrusted data to `Case07B.handleSink()`
- **Case07B.java, line 29**: `String search = "(cn=" + data + ")"` concatenates the untrusted input directly into the LDAP filter string
- **Case07B.java, line 32**: `directoryContext.search("", search, null)` executes the tainted LDAP filter

## Fix
The fix requires escaping special LDAP filter characters according to RFC 2254 before using the user input in the filter string. Add an escape method and apply it to the data.

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
    private static String escapeLdapFilterString(String value) {
        if (value == null) {
            return "";
        }
        
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '*':
                    result.append("\\2a");
                    break;
                case '(':
                    result.append("\\28");
                    break;
                case ')':
                    result.append("\\29");
                    break;
                case '\\':
                    result.append("\\5c");
                    break;
                case '/':
                    result.append("\\2f");
                    break;
                case '\0':
                    result.append("\\00");
                    break;
                default:
                    result.append(c);
            }
        }
        return result.toString();
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
            
            String search = "(cn=" + escapeLdapFilterString(data) + ")";

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
The fix adds an `escapeLdapFilterString()` method that escapes RFC 2254 special LDAP filter characters: `*`, `(`, `)`, `\`, `/`, and the NUL character. Each special character is replaced with its hexadecimal escape sequence (e.g., `*` becomes `\2a`).

At line 33 (formerly line 29), the untrusted input is now passed through the escape method before being concatenated into the filter string: `String search = "(cn=" + escapeLdapFilterString(data) + ")"`. This ensures that any LDAP metacharacters in the user input are treated as literal characters rather than filter syntax, preventing injection attacks.

The fix maintains the original functionality while neutralizing the attacker's ability to craft filter expressions through malicious input.
