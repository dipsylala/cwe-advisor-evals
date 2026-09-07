## Verdict
CONFIRMED - CWE-90 LDAP Injection at line 32. The `data` parameter is directly concatenated into an LDAP filter string without escaping LDAP special characters, allowing filter injection.

## Source
The vulnerability exists in the call chain:
- **Case17A.java (line 18)**: Calls `Case17B().handleSink(data, ...)` with `data = "foo"`
- **Case17B.java (line 29)**: Concatenates `data` directly into LDAP filter: `String search = "(cn=" + data + ")";`
- **Case17B.java (line 32)**: Uses the unescaped filter in LDAP search: `directoryContext.search("", search, null)`

An attacker controlling `data` can inject LDAP filter syntax (e.g., `*)(cn=*` to bypass authentication or extract directory entries).

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
    private static String escapeLdapFilterChars(String input) {
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
            
            String search = "(cn=" + escapeLdapFilterChars(data) + ")";

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
The fix adds an `escapeLdapFilterChars()` method that escapes LDAP filter special characters according to RFC 4515:
- `*` → `\2a`
- `(` → `\28`
- `)` → `\29`
- `\` → `\5c`
- NUL → `\00`

Line 33 (previously line 29) now calls this method on `data` before constructing the LDAP filter:
```
String search = "(cn=" + escapeLdapFilterChars(data) + ")";
```

This ensures that any special LDAP characters in the input are neutralized and treated as literal characters, preventing filter injection. The vulnerability is fixed at the source by sanitizing user-controlled input before it reaches the LDAP sink.
