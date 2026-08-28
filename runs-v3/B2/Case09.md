# Case09 - CWE-90 (LDAP Injection)

- **cwe_id**: CWE-90
- **location**: `evals/cases-v2/Case09/Case09E.java`, line 32 (filter built at line 29)
- **confidence**: high

## Verdict

exploitable

## Source

Untrusted data enters at `Case09A.handle()` line 16 as `request.getParameter("name")` - an
unvalidated HTTP request parameter. It is passed unchanged through four hops:

1. `Case09A.handle()` line 18 -> `new Case09B().handleSink(data, request, response)`
2. `Case09B.handleSink()` line 13 -> `new Case09C().handleSink(data, ...)`
3. `Case09C.handleSink()` line 13 -> `new Case09D().handleSink(data, ...)`
4. `Case09D.handleSink()` line 13 -> `new Case09E().handleSink(data, ...)`

No validation, allowlist check, encoding, or reassignment occurs anywhere on that path. In
`Case09E.handleSink()` the value is concatenated into an LDAP search filter at line 29
(`String search = "(cn=" + data + ")";`) and that string reaches the sink at line 32,
`directoryContext.search("", search, null)`. Because the filter is parsed as an expression
tree, a value such as `*)(objectClass=*` closes the `cn` term and opens an attacker-chosen
one, and a bare `*` converts the equality test into a match-everything wildcard. Every
matched entry's attributes are then written out by the loop at lines 33-47, so the injected
filter's results are returned to the requester.

Sink contract before the change: `search(String, String, SearchControls)` returns a
`NamingEnumeration<SearchResult>` that the method iterates to print every attribute value;
nothing is discarded; the third argument is `null`, which JNDI documents as equivalent to
`new SearchControls()` (ONELEVEL scope, all attributes returned, no count or time limit);
failures surface as `NamingException`, caught and logged at line 49.

## Fix

Complete fixed `Case09E.java`:

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

            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[] { data }, null);
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

Vulnerable lines replaced:

```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null); // filter structure comes from user input
```

No new dependency is required - the parameterized overload is part of `javax.naming.directory.DirContext`
in the JDK. If an allowlist on `name` is wanted as defence in depth, apply it in `Case09A` before the
value is forwarded, and pass the canonical allowlisted value onward rather than the raw parameter.

## Explanation

The filter is no longer assembled by string concatenation. The template `"(cn={0})"` is now a
fixed, developer-controlled expression and the untrusted value is supplied separately through
the `filterArgs` array of the four-argument `DirContext.search(String, String, Object[], SearchControls)`
overload. JNDI substitutes each argument as a filter *value*, escaping the LDAP metacharacters
(`*`, `(`, `)`, backslash, NUL) per RFC 2254 before the filter is sent to the directory, and the
substituted text is not re-parsed as filter syntax. That means the query's structure can no longer
be influenced by the request parameter: a payload like `*)(objectClass=*` becomes a literal `cn`
value that simply matches nothing, instead of closing the `cn` term and opening an attacker-chosen
one. The search base, search scope, returned attributes, result iteration, output, exception
handling, and context cleanup are all left exactly as they were, so the fix is confined to the
one mechanism that made the weakness possible.

## Behaviour changes

- **none beyond closing the weakness.** The `SearchControls` argument stays `null`; JNDI documents
  a `null` value on this overload as equivalent to `new SearchControls()`, the same default the
  original three-argument call used, so search scope, returned attributes, and count/time limits
  are unchanged. The search base remains `""`, the return value remains a
  `NamingEnumeration<SearchResult>` consumed by the same loop, nothing previously discarded is
  now surfaced, and failures still arrive as `NamingException` and are logged by the existing
  handler.
- One consequence inherent to the fix, called out for reviewers: LDAP metacharacters in the `name`
  parameter are now matched literally rather than interpreted. A caller who was relying on
  submitting `*` to run a wildcard `cn` search will get an exact-match lookup instead. That is the
  weakness being removed, not an incidental change; if wildcard search is a genuine requirement,
  it must be expressed in the developer-controlled template (for example `"(cn={0}*)"`), never
  taken from the parameter.

## Assumptions

- The finding's language was inferred as Java from the `.java` extension and JNDI imports; no
  Spring LDAP or ESAPI dependency is visible in the case, so the JDK-native parameterized
  overload was chosen over `LdapQueryBuilder` or `encodeForDN()`. The value flows into a search
  *filter*, not a DN, so filter-level (RFC 2254/4515) escaping is the correct context.
- Autonomous mode: no code was modified: the above is a proposal only.
