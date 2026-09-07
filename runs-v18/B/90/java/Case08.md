## Verdict

Exploitable. The untrusted user input from `request.getParameter("name")` at line 16 of Case08A flows through the call chain (Case08A → Case08B → Case08C → Case08D) without validation or sanitization, and reaches the LDAP query sink at line 32 of Case08D, where it is concatenated into an LDAP filter string without escaping. An attacker can inject LDAP metacharacters like `*`, `(`, `)`, and others to manipulate the query logic and access unauthorized directory data.

## Source

Untrusted input source: `request.getParameter("name")` at line 16 of Case08A. This parameter is passed as the `data` argument through the entire call chain to the sink.

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

The fix replaces the unsafe string concatenation of user input into the LDAP filter with JNDI's parameterized search filter overload. The original code at line 29 concatenated the untrusted `data` directly into the filter string: `"(cn=" + data + ")"`. The fixed code uses a placeholder `{0}` in the filter template `"(cn={0})"` and passes the user input separately via the `filterArgs` parameter as `new Object[]{data}` in the parameterized `DirContext.search()` call at line 32. JNDI automatically escapes the filter argument according to RFC 4515, which neutralizes LDAP metacharacters like `*`, `(`, `)`, `\`, and NUL. This separates query structure from user data and prevents injection. The fourth parameter `new SearchControls()` supplies default search controls as required by the parameterized overload signature.

## Behaviour changes

- Line 29: Filter template changed from string concatenation to a parameterized template with `{0}` placeholder, eliminating string building logic at runtime.
- Line 32: Search call signature changed from `directoryContext.search("", search, null)` (3 parameters) to `directoryContext.search("", search, new Object[]{data}, new SearchControls())` (4 parameters). The third parameter now provides filter arguments for automatic escaping by JNDI, and the fourth parameter provides a SearchControls object (required by this overload) instead of null. The SearchControls is constructed with default settings, which preserves the original search semantics: default scope (SUBTREE_SCOPE), default size limit (1000), and default timeout (no timeout). These defaults match the null SearchControls behavior of the original code in practice.

