## Verdict

**CONFIRMED**: CWE-90 LDAP Injection at line 32 of Case08D.java. The `data` parameter flows from user input (request parameter "name" in Case08A) through the call chain (Case08B → Case08C → Case08D) and is concatenated directly into the LDAP search filter without escaping special LDAP characters, allowing an attacker to modify the filter logic.

## Source

User input enters at Case08A line 16:
```
data = request.getParameter("name");
```

The data flows through Case08B and Case08C unchanged, arriving at Case08D where it is concatenated into an LDAP filter on line 29 and used as an LDAP search argument on line 32:
```
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

An attacker can inject LDAP filter metacharacters (e.g., `*`, `(`, `)`, `\`) to modify the search logic, bypass authentication, or extract unintended directory entries.

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
            
            String search = "(cn=" + escapeLDAPSearchFilter(data) + ")";

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

    private static String escapeLDAPSearchFilter(String filter)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < filter.length(); i++) {
            char c = filter.charAt(i);
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
}
```

## Explanation

The vulnerability is fixed by escaping LDAP special characters in the user-supplied data before constructing the search filter. The `escapeLDAPSearchFilter()` method replaces dangerous metacharacters with their hex-encoded equivalents as defined in RFC 4515:
- `\` (backslash) → `\5c`
- `*` (asterisk/wildcard) → `\2a`
- `(` (left paren) → `\28`
- `)` (right paren) → `\29`
- Null byte → `\00`

This prevents the attacker from breaking out of the filter string context or altering the search logic. For example:
- Input: `admin*))(&(uid=*` 
- After escaping: `admin\2a\29\29\28&\28uid\3d*`
- Result: Literal search for the entire string, not filter injection

The escaping is applied at the point of use (line 29, now called `escapeLDAPSearchFilter(data)`), maintaining the original data flow while neutralizing the injection vector at the LDAP sink.
