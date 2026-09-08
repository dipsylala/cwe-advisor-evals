## Verdict
Confirmed. `Case07B.handleSink` builds an LDAP search filter by directly concatenating attacker-controlled input, allowing filter-syntax injection.

## Source
`Case07A.handle` reads the untrusted value from `request.getParameter("name")` and passes it unchanged into `Case07B.handleSink(data, request, response)`.

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

            String filterExpr = "(cn={0})";
            Object[] filterArgs = new Object[] { data };
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            // Filter arguments are escaped by the JNDI provider per RFC 4515,
            // so attacker-controlled data cannot break out of the filter clause.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", filterExpr, filterArgs, searchControls);
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
The original code built the filter with `"(cn=" + data + ")"` and passed the finished string straight to `DirContext.search(name, filter, SearchControls)`. Any LDAP filter metacharacter in `data` (`)`, `(`, `*`, `\`, or a NUL byte) is interpreted as filter syntax, letting an attacker close the `cn` clause early and append arbitrary filter terms (e.g. `*)(uid=*))(|(uid=*`) to alter which directory entries are returned, or inject wildcards to broaden matches.

The fix switches to the `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload, using a parameterized filter template (`"(cn={0})"`) with the untrusted value supplied only through `filterArgs`. Per the JNDI specification, each `{i}` placeholder is substituted with the corresponding argument after the provider escapes any LDAP filter special characters in its string form, so the value can no longer terminate or extend the filter clause regardless of its content. This mirrors using a parameterized query for SQL: the structure of the filter is fixed by the literal template, and the data is always treated as a value, never as filter grammar. A `SearchControls` instance is required by this overload (the original passed `null`), so `SUBTREE_SCOPE` is set explicitly, preserving the search's original behavior of searching the whole subtree from `""`.
