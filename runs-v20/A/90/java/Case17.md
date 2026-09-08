## Verdict

Confirmed. `Case17B.handleSink` builds an LDAP search filter by concatenating attacker-influenced input directly into the filter string, then passes that string to `DirContext.search`. Special LDAP filter characters in the input (`*`, `(`, `)`, `\`, NUL) are not escaped, so the input can alter the filter's logical structure (classic LDAP filter injection, e.g. widening `(cn=foo)` into `(cn=*)` or appending extra conditions).

## Source

`data`, received as a parameter of `Case17B.handleSink(String data, HttpServletRequest request, HttpServletResponse response)`, called from `Case17A.handle` as `(new Case17B()).handleSink(data, request, response)`. It flows unmodified into the filter string built on line 29 (`String search = "(cn=" + data + ")";`) and reaches the sink at line 32 (`directoryContext.search("", search, null)`).

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

            // Using the filterArgs overload lets the JNDI provider substitute the
            // value into the filter itself, escaping LDAP filter metacharacters
            // (*, (, ), \, NUL) per RFC 2254 instead of concatenating raw input.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", filterExpr, filterArgs, null);
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

The vulnerability was the manual string concatenation on line 29 building `"(cn=" + data + ")"` and handing that raw string straight to `DirContext.search(name, filterExpr, cons)`. Any LDAP filter metacharacter in `data` (`*`, `(`, `)`, `\`, or a NUL byte) is interpreted by the LDAP filter parser rather than treated as literal text, letting an attacker widen the search (e.g. injecting `*)(uid=*` style payloads) or otherwise change which entries are matched or returned.

The fix replaces the ad hoc concatenation with the JNDI overload `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)`. The filter expression now contains only a placeholder, `(cn={0})`, and `data` is passed separately in `filterArgs`. Per the `javax.naming.directory.DirContext` contract, the provider substitutes each `{i}` placeholder with the corresponding argument and escapes any LDAP filter special characters in that value before insertion (the same RFC 2254 escaping rule `SearchFilter.format`/JNDI's internal encoder applies), so the value can no longer break out of the `cn` attribute comparison regardless of its content. This is the standard, provider-level defence for JNDI/LDAP filter injection: it keeps the query semantics intact (a literal `cn` lookup) while removing the injection channel, and it requires no separate allowlist or manual escaping routine that would need to be kept in sync with the LDAP filter grammar. The rest of the method (context setup, result iteration, exception handling, and resource cleanup) is unchanged.
