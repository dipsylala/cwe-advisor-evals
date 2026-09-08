## Verdict

Confirmed. `Case09A.handle` reads the untrusted `name` request parameter and passes it unmodified through `Case09B` -> `Case09C` -> `Case09D` -> `Case09E.handleSink`, where it is concatenated directly into an LDAP search filter (`"(cn=" + data + ")"`) and passed to `DirContext.search(...)`. An attacker-supplied value containing LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) can alter the filter's logical structure - broadening the search, injecting extra filter clauses, or causing the query to match unintended entries.

## Source

`Case09A.java`, line 10: `data = request.getParameter("name");` - attacker-controlled HTTP request parameter, passed unsanitized through the call chain to the LDAP search sink in `Case09E.java` line 32.

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

            String search = "(cn=" + escapeLDAPSearchFilter(data) + ")";

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

    /**
     * Escapes the RFC 4515 special characters in a value that will be embedded in an
     * LDAP search filter, so it can only ever be interpreted as a literal filter value
     * and cannot inject additional filter clauses or wildcards.
     */
    private static String escapeLDAPSearchFilter(String input)
    {
        if (input == null)
        {
            return "";
        }

        StringBuilder escaped = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++)
        {
            char currentChar = input.charAt(i);
            if (currentChar == '\\')
            {
                escaped.append("\\5c");
            }
            else if (currentChar == '*')
            {
                escaped.append("\\2a");
            }
            else if (currentChar == '(')
            {
                escaped.append("\\28");
            }
            else if (currentChar == ')')
            {
                escaped.append("\\29");
            }
            else if (currentChar == 0)
            {
                escaped.append("\\00");
            }
            else
            {
                escaped.append(currentChar);
            }
        }
        return escaped.toString();
    }
}
```

## Explanation

The filter string `"(cn=" + data + ")"` treats `data` as trusted structure rather than a literal value, so any RFC 4515 metacharacter it contains (`*`, `(`, `)`, `\`, NUL) is interpreted by the LDAP server as filter syntax instead of literal text - for example a value of `*)(uid=*))(|(cn=*` closes the intended clause early and appends attacker-chosen filter terms, letting the search return arbitrary or unintended directory entries.

The fix keeps the query logic and structure unchanged (no format or API swap) and instead neutralizes the injection at the point the untrusted value is embedded: each of the five RFC 4515 special characters is backslash-hex-escaped before concatenation, per the standard LDAP filter-escaping scheme (checking `\` first so the escape sequences produced for the other characters are not themselves re-interpreted). After escaping, `data` can only ever appear as the literal value of the `cn` attribute test - it can no longer terminate or extend the filter, so the search is constrained to the single intended clause regardless of its content. The JNDI API used (`DirContext.search`) is unaffected; only the value assembled into the filter string changes.
