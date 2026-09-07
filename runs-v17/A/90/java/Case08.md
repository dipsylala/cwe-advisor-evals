## Verdict
Confirmed CWE-90 (LDAP Injection) vulnerability at line 32. User input from the request parameter flows through the call chain (Case08A → Case08B → Case08C → Case08D) and is directly concatenated into an LDAP filter string without escaping, allowing filter metacharacter injection.

## Source
Line 32 in Case08D.java: `NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);`

The vulnerability arises from line 30-31:
```java
String search = "(cn=" + data + ")";
```

User input `data` (from request parameter "name") is not escaped before being used as a component of an LDAP filter. An attacker could inject LDAP filter operators like `*`, `(`, or `)` to manipulate query logic.

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
            
            String escapedData = escapeLdapFilterValue(data);
            String search = "(cn=" + escapedData + ")";

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

    private static String escapeLdapFilterValue(String value)
    {
        if (value == null)
        {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);
            switch (c)
            {
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
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}
```

## Explanation
The fix escapes all LDAP filter metacharacters in the user-supplied input before constructing the filter string. The `escapeLdapFilterValue()` method implements RFC 4515 escaping by replacing special characters with their hex escape sequences:

- `*` (wildcard) → `\2a`
- `(` (filter start) → `\28`
- `)` (filter end) → `\29`
- `\` (escape character) → `\5c`
- NUL → `\00`

This prevents an attacker from injecting LDAP filter syntax. For example, input like `admin*` becomes `admin\2a` when used in the filter, matching only the literal string "admin*" rather than any username starting with "admin".

The escaping is applied at line 31 before the filter string is constructed, ensuring all user input is neutralized before reaching the `directoryContext.search()` sink at line 33.
