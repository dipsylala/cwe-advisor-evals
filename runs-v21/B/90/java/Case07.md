## Verdict

Exploitable. The untrusted user input from `request.getParameter("name")` is directly concatenated into an LDAP search filter without escaping, allowing an attacker to inject LDAP syntax and modify the search query.

## Source

Line 16, Case07A.java: `data = request.getParameter("name");` — untrusted HTTP parameter passed to Case07B.handleSink() at line 18.

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
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        Hashtable<String, String> environmentHashTable = new Hashtable<String, String>();
        environmentHashTable.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        environmentHashTable.put(Context.PROVIDER_URL, "ldap://localhost:389");
        DirContext directoryContext = null;

        try
        {
            directoryContext = new InitialDirContext(environmentHashTable);
            
            String searchFilter = "(cn={0})";
            Object[] filterArgs = {data};
            SearchControls searchControls = new SearchControls();

            // Fixed: Using parameterized filter with separate filterArgs to prevent LDAP injection
            NamingEnumeration<SearchResult> answer = directoryContext.search("", searchFilter, filterArgs, searchControls);
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

The vulnerability was caused by concatenating untrusted user input directly into an LDAP search filter string at line 29 (`String search = "(cn=" + data + ")"`), which was then passed to `directoryContext.search()` at line 32. This allows an attacker to inject LDAP metacharacters like `*`, `(`, and `)` to modify the query logic — for example, input like `*)(uid=*))(|(uid=*` would change the search semantics.

The fix replaces string concatenation with JNDI's parameterized `DirContext.search()` overload. Instead of building the filter string by concatenation, we use a placeholder `{0}` in the filter string and pass the user input as a separate element in the `Object[] filterArgs` array. The JNDI implementation automatically escapes the value according to RFC 4515 (LDAP search filter escaping rules) before substituting it into the filter, preventing any injected metacharacters from being interpreted as syntax. We also instantiate a `SearchControls` object to satisfy the required method signature, using the default scope and other settings.

## Behaviour changes

One new variable introduced: `SearchControls searchControls = new SearchControls()`. This provides the search controls argument required by the parameterized `DirContext.search(name, filterExpr, filterArgs, cons)` signature. The SearchControls object is created with all default values, preserving the original search behavior while enabling the secure parameterized API. No functional behavior change to the search scope or returned attributes — the original code passed `null` for controls, which the parameterized overload does not accept, so this uses the default SearchControls which applies the same defaults that were in effect before.
