## Verdict

Real vulnerability confirmed. LDAP injection at line 32 of Case17B.java.

## Source

Line 29-32 in Case17B.java:
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

The `data` parameter is user-controlled (passed from Case17A where it originates from request handling) and is directly concatenated into the LDAP filter string without escaping. LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) are not escaped, allowing an attacker to inject filter logic.

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
    /**
     * Escapes LDAP filter metacharacters according to RFC 4515.
     */
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
            
            String search = "(cn=" + escapeLdapFilter(data) + ")";

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

The vulnerability stems from directly embedding untrusted user input into an LDAP filter string. LDAP filter syntax uses special characters (`*`, `(`, `)`, `\`, NUL) for query operators; an attacker can inject these to alter the filter logic, escape the intended scope, or bypass authentication checks.

The fix implements RFC 4515 escaping via the `escapeLdapFilter()` method, which replaces each LDAP metacharacter with its escaped hex sequence. For example, input like `*)(mail=*))(&(uid=*` is rendered harmless by escaping the metacharacters, forcing the LDAP server to treat them as literal characters in the `cn` attribute value.

Line 29 now calls `escapeLdapFilter(data)` before concatenating, ensuring any injected filter syntax is neutralized. The LDAP search at line 32 then operates on a safe filter string that cannot be manipulated by the attacker.
