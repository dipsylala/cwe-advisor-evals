## Verdict

Confirmed - exploitable LDAP injection.

## Source

`Case09A.handle()` reads `request.getParameter("name")` (attacker-controlled HTTP request parameter) into `data`, which is passed unmodified through `Case09B.handleSink()` -> `Case09C.handleSink()` -> `Case09D.handleSink()` -> `Case09E.handleSink()`. No validation, escaping, or transformation occurs anywhere along the chain.

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
            Object[] filterArgs = new Object[] { data };

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

The original code built the filter by string concatenation (`"(cn=" + data + ")"`) and passed it to the 3-argument `DirContext.search(name, filterExpr, cons)` overload with `cons` given as `null`. Any LDAP metacharacter in `data` - `)`, `(`, `*`, or a backslash - is interpreted as filter syntax, letting an attacker close the `cn` clause and append arbitrary additional filter terms (classic LDAP filter injection), or turn the equality test into a wildcard match with a bare `*`.

The fix replaces concatenation with JNDI's parameterized search: the filter string uses a `{0}` placeholder and the untrusted value is passed separately via the `filterArgs` array. JNDI escapes each `String`-typed filter argument per RFC 4515 before substitution, so any metacharacters in `data` are neutralized as literal data rather than parsed as filter syntax. Because the 4-argument overload that accepts `filterArgs` requires a trailing `SearchControls` argument (there is no 3-argument overload that takes `filterArgs` without it), `new SearchControls()` is passed explicitly - this reproduces the exact default behaviour the original `null` argument to the 3-arg overload already had (per `DirContext.search`'s Javadoc, a `null` `SearchControls` is equivalent to a default-constructed one), so search scope and returned-attribute behaviour are unchanged.

## Behaviour changes

None. The return type (`NamingEnumeration<SearchResult>`), the search base (`""`), the effective search scope and returned-attribute set (default `SearchControls`, identical to the previous implicit `null`), the loop that consumes results, and the exception/logging/cleanup behaviour are all unchanged. The only functional difference is that filter metacharacters in `data` are now escaped instead of parsed as filter syntax - a value containing `*`, `(`, `)`, or `\` now matches only a `cn` literally equal to that string (or matches nothing) instead of altering the query structure.

Verification performed: the fixed sink block was extracted and compiled standalone against the real `javax.naming`/`javax.naming.directory` API with `javac` (JDK 26) - it compiled cleanly, confirming the `search(String, String, Object[], SearchControls)` overload, its argument types, and the `SearchControls` no-arg constructor all resolve as used. The servlet-fixture classes (`testcasesupport.*`, `IO`) are outside javac's reachable classpath in this environment and were checked by hand instead: no new symbols from those packages were introduced, and every existing reference to them is unchanged from the original file.
