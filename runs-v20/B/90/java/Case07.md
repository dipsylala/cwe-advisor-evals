## Verdict

Exploitable. Confidence: high.

- CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query / LDAP Injection)
- Location: `Case07B.java`, line 32, inside `handleSink`
- Sink: `DirContext.search("", search, null)`, where `search` is `"(cn=" + data + ")"`

## Source

`Case07A.handle(HttpServletRequest, HttpServletResponse)` reads `data = request.getParameter("name")` from the HTTP request with no validation or encoding, then passes `data` unchanged to `(new Case07B()).handleSink(data, request, response)`. `Case07B.handleSink` concatenates `data` directly into an LDAP filter string, `"(cn=" + data + ")"`, and passes that string to `DirContext.search()`. Nothing between the source and the sink validates, escapes, or otherwise constrains `data`, so an attacker-supplied value such as `*)(|(cn=*` reaches the LDAP filter parser intact and can widen or rewrite the search.

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

            String search = "(cn={0})";
            Object[] filterArgs = new Object[] { data };

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, new SearchControls());
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

The fix replaces string concatenation with JNDI's parameterized search overload: the filter is now the fixed template `"(cn={0})"` and `data` is passed separately as `filterArgs[0]`. Per the `DirContext.search(Name/String, String, Object[], SearchControls)` Javadoc, each `String`-valued element of `filterArgs` is substituted into the corresponding `{i}` placeholder after being escaped according to RFC 2254 (RFC 4515) - the characters `*`, `(`, `)`, `\`, and NUL are neutralized before the value ever becomes part of the filter's grammar, so an injected `)` or `*` in `data` can no longer close the `cn` term or open a new one. Query structure and data are kept separate by the API itself rather than by ad hoc escaping, which closes the injection at the sink identified in the trace.

## Behaviour changes

- **`search` string changed from a concatenated literal to the placeholder `"(cn={0})"`, with `data` moved into a new `filterArgs` array.** Required to use the parameterized overload; for any value of `data` that contains no LDAP metacharacters the resulting filter is identical to the original, and for values that do contain metacharacters the original was exploitable while the fix now treats them as literal text of the `cn` value (the correct behaviour).
- **`search()` call gains a fourth argument, `new SearchControls()`, replacing the original three-argument call whose third argument was `null`.** Not a functional change: `DirContext.search(String, String, SearchControls)`'s Javadoc states that a `null` `cons` argument is equivalent to passing `new SearchControls()` (default object-scope search, no attribute filtering, no size/time limits). The explicit object is required only because the `filterArgs`-accepting overload has no three-argument form - passing `null` there would NPE where the constructor calls `cons.getSearchScope()` internally. The same default scope, returned attributes, and result type (`NamingEnumeration<SearchResult>`) are preserved, and the `NamingException` handling and `finally`-block cleanup are untouched.
- No other lines changed. `Case07A.java` is unaffected and not included above.

**Verification:** Copied `Case07B.java` (with minimal local stubs for `testcasesupport.IO` and the `javax.servlet.http` interfaces, which are not part of the JDK) to a scratch directory outside the repository and compiled the fixed version with `javac --release 17`. It compiled with zero errors or warnings. (A same-directory compile under the installed JDK 26 without `--release` reports an unrelated `java.lang.IO` vs `testcasesupport.IO` ambiguity - a JDK-26-preview naming collision against the stub package name, reproducible identically against the original, unmodified file, and not something the fix introduces.) All APIs used - `DirContext.search(String, String, Object[], SearchControls)` and `javax.naming.directory.SearchControls` - are standard JDK `java.naming` classes already imported in the file via `javax.naming.directory.*`; no new dependency or import was added.
