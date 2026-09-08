## Verdict

Exploitable. `cwe_id`: CWE-90 (LDAP Injection). `confidence`: high.

## Source

`Case08A.handle()`, line 16: `data = request.getParameter("name");` - an HTTP request parameter, fully attacker-controlled, with no validation or encoding applied anywhere along the call chain.

Call chain: `Case08A.handle()` -> `Case08B.handleSink(data, ...)` -> `Case08C.handleSink(data, ...)` -> `Case08D.handleSink(data, ...)`. The tainted `data` value passes through B and C as a plain parameter with no transformation.

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

            // FIX: filter value passed via filterArgs so JNDI escapes it per RFC 4515 instead of being concatenated into the filter string.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[] { data }, new SearchControls());
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

The sink built an LDAP search filter by concatenating the raw request parameter directly into the filter string (`"(cn=" + data + ")"`), so a value such as `*)(cn=*` or `admin)(|(cn=*` could close the intended clause and inject arbitrary filter logic, turning an equality search into a wildcard disclosure or a crafted boolean expression. The fix keeps `"(cn={0})"` as a literal filter template and moves `data` into the `filterArgs` array of the four-argument `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload. Per the JNDI Javadoc, a `String`-valued filter argument is escaped according to RFC 2254 (now RFC 4515) before substitution, so `*`, `(`, `)`, backslash and NUL in `data` are neutralized and can no longer alter the filter's structure; only the value position of `cn=` changes, not the query's shape.

## Behaviour changes

- **`SearchControls` argument added.** The original call was the three-argument `search(String, String, SearchControls)` overload with `null` passed for `cons`; per the JNDI Javadoc, `null` there is equivalent to a default-constructed `SearchControls()` (one-level scope, no count/time limit, no attribute filtering, no dereferencing of links, no returned objects). The parameterized four-argument overload has no `filterArgs`-only three-argument form, so an explicit `new SearchControls()` is required and reproduces the exact same default behaviour rather than changing it - the knowledge base's own remediation guidance calls this out as the required substitution when the original call left the controls argument as the default. `none` beyond this required, behaviour-preserving addition.
- Filter text changed from `"(cn=" + data + ")"` to the literal `"(cn={0})"` with `data` supplied separately as `filterArgs[0]`; for any input that contains no LDAP metacharacters this produces an identical filter and identical results. For input that does contain metacharacters, the value is now escaped rather than interpreted as filter syntax - this is the intended closure of the weakness, not an unintended behaviour change.
- No change to what the method returns, what it logs, or its exception handling; `Case08A`, `Case08B`, and `Case08C` are unmodified since `data` was already passed through unaltered and the fix only needed to change how it is used at the sink.

## Verification

Compiled an isolated snippet reproducing the changed block (`Hashtable`/`InitialDirContext` setup, the `directoryContext.search("", filter, new Object[]{data}, new SearchControls())` call, and the result-iteration loop) with `javac` (JDK 26, `javax.naming`/`javax.naming.directory` from the `java.naming` module) - compiled cleanly with no errors or warnings. The full four-file chain was not compiled because `testcasesupport.*` and `javax.servlet.http.*` are external to the changed code and not available in the check environment; by hand, `SearchControls` is already covered by the file's existing `import javax.naming.directory.*;`, `directoryContext.search(String, String, Object[], SearchControls)` is a real `javax.naming.directory.DirContext` method (confirmed by the successful isolated compile), and every other identifier in the changed lines (`NamingEnumeration`, `SearchResult`) was already present and unchanged in the original file.

## Assumptions

None - the source, sink, and applicable safe pattern (JNDI parameterized filter, `cwe/90/java/INDEX.md`) were unambiguous.
