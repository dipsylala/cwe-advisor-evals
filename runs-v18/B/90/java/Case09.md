## Verdict

**CONFIRMED** - LDAP Injection vulnerability in Case09E.java line 32. Untrusted user input from HTTP request parameter is concatenated directly into an LDAP filter without escaping, allowing an attacker to inject LDAP metacharacters and manipulate query structure.

## Source

Case09A: HTTP request parameter "name" → Case09B → Case09C → Case09D → Case09E

Attacker-controlled input flows from `request.getParameter("name")` through the call chain to the vulnerable sink.

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

            String search = "(cn={0})";

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[]{data}, new SearchControls());
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

The vulnerability was fixed by replacing string concatenation in the LDAP filter with JNDI's built-in parameterized search method. 

**Changes made:**
1. Line 25: Changed from `String search = "(cn=" + data + ")";` to `String search = "(cn={0})";` - the filter now uses a placeholder `{0}` instead of concatenating user input
2. Line 32: Changed from `directoryContext.search("", search, null)` to `directoryContext.search("", search, new Object[]{data}, new SearchControls())` - the method now uses the four-argument overload that accepts `filterArgs`

**Why this fixes the vulnerability:**
JNDI's parameterized `DirContext.search()` method with the `filterArgs` parameter automatically escapes each string-valued argument according to RFC 4515 (LDAP filter escaping rules). This separates the query structure from user data, preventing metacharacters like `*`, `(`, `)`, `\`, and NUL from being interpreted as LDAP operators. The JNDI implementation handles the escaping internally, ensuring that injected LDAP syntax is treated as literal data rather than query operators.

The four-argument overload signature used is: `search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` where:
- `name`: The search base ("" for root)
- `filterExpr`: The LDAP filter template with placeholders
- `filterArgs`: An Object array containing the untrusted data to be safely escaped
- `cons`: SearchControls object for search parameters (using default scope)

## Behaviour changes

**Functional impact:** None. The query behavior remains identical - it still searches for directory entries where the `cn` attribute matches the provided data value. The only difference is that metacharacters in the input are now escaped and treated as literal characters rather than LDAP syntax operators.

**Security impact:** Critical. The vulnerability is eliminated. Attackers can no longer use special LDAP characters to modify query structure or perform privilege escalation. For example, an attacker input like `*)(uid=*` is now safely escaped and searched for literally in the `cn` attribute, rather than being parsed as LDAP operators.

**Error handling:** The existing error handling behavior is preserved. The try-catch block still catches `NamingException` in the same way, and the finally block still closes the `DirContext`.
