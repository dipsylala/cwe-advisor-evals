# Case07 - CWE-90 (LDAP Injection)

## Verdict

exploitable

## Source

Untrusted data enters at `Case07A.handle()` (`Case07A.java:16`) as the HTTP request parameter
`name`: `data = request.getParameter("name");`. It is attacker-controlled and unvalidated.

Path to the sink:

1. `Case07A.java:16` - `data = request.getParameter("name")` (source, taint introduced).
2. `Case07A.java:18` - `(new Case07B()).handleSink(data, request, response)` passes the tainted
   value across the call boundary with no validation, escaping, or length/character restriction.
3. `Case07B.java:17` - `handleSink(String data, ...)` receives the value unchanged.
4. `Case07B.java:29` - `String search = "(cn=" + data + ")";` concatenates the tainted value
   directly into an LDAP search filter expression.
5. `Case07B.java:32` - `directoryContext.search("", search, null)` (sink) parses that string as an
   RFC 4515 filter and executes it against the directory.

Nothing on the path escapes or constrains the value, so filter metacharacters survive intact. A
value such as `*` turns the equality test into a match-everything wildcard, and
`*)(objectClass=*` closes the `cn` term and opens an attacker-chosen one, producing the filter
`(cn=*)(objectClass=*)`. Because the loop at `Case07B.java:33-47` writes every attribute of every
returned entry to the response via `IO.writeLine`, a successful injection discloses directory
content the query was never meant to return.

## Fix

Complete fixed `Case07B.java`:

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

Only two lines change. Vulnerable form:

```java
String search = "(cn=" + data + ")";                                            // tainted value becomes filter syntax
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

Fixed form:

```java
String search = "(cn={0})";                                                     // filter structure is now a constant
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[] { data }, null);
```

No new dependency is required - the parameterized overload is part of `javax.naming.directory.DirContext`
in the JDK, so there is no library version to pin or check.

## Explanation

The filter string is now a fixed constant containing a `{0}` placeholder, and the untrusted value
is passed separately through the `filterArgs` array of JNDI's parameterized
`DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)`
overload. The provider substitutes the argument as a filter *value* and escapes the RFC 4515
metacharacters (`*`, `(`, `)`, backslash, NUL) as it does so, so the query's expression tree is
determined entirely by the constant and cannot be reshaped by input. A payload like
`*)(objectClass=*` is now matched literally as a `cn` value instead of closing the `cn` term and
opening an attacker-chosen one, which removes the injection point rather than filtering for known
bad input. This is preferred over a hand-written escape routine or a denylist, both of which
repeatedly miss part of the character set; the escaping here is performed by the same layer that
parses the filter. The search base, search controls, result handling, and error handling are all
left as they were, so the change is confined to how the value reaches the filter.

## Behaviour changes

- **Filter metacharacters in `name` are now literal.** This is the intended effect of the fix, but
  it is user-visible: a request such as `?name=Ali*` previously performed a prefix wildcard search
  and now searches for the literal `cn` value `Ali*`, returning no match. If wildcard search is a
  deliberate feature, it must be reintroduced explicitly - by validating the input against an
  allowlist and building the intended wildcard pattern from server-controlled parts - not by
  restoring concatenation.
- **Malformed input no longer produces a filter parse error.** Previously a value containing an
  unbalanced `)` produced an invalid filter and an `InvalidSearchFilterException`, caught by the
  existing `NamingException` handler and logged at `WARNING`. That value is now escaped and
  searched for literally, so the call succeeds and returns an empty result set. Callers that
  relied on the exception as an input-validation signal (none do here) would be affected.
- **Search scope and returned attributes are unchanged.** The `null` `SearchControls` argument is
  carried over deliberately into the 4-argument overload, where it has the identical meaning -
  the JDK substitutes the default `new SearchControls()`, i.e. one-level scope, all attributes
  returned, no count or time limit. Supplying a populated `SearchControls` object instead would
  have been a silent scope change, so it was not done.
- **Search base, return value, and result handling are unchanged.** The base name stays `""`, the
  call still returns `NamingEnumeration<SearchResult>`, and the enumeration is consumed by the
  same loops writing the same `" Value: "` output. No output the original discarded is surfaced,
  and no output it produced is dropped.
- **Exception and cleanup behaviour is unchanged.** The parameterized overload throws the same
  `NamingException` hierarchy, so the existing `catch` and the `finally` block that closes the
  `DirContext` continue to apply unmodified.
- **Not changed, and noted for the reviewer:** no allowlist validation was added on `data`, since
  the parameterized filter is the operative control and adding a character or length restriction
  would reject inputs the application currently accepts. If defence in depth is wanted, validate
  `name` against the expected `cn` format before the search and reject non-conforming values. The
  bind here is anonymous against `ldap://localhost:389`; confirming that the account the
  application binds with is read-only and scoped to the intended subtree limits the reach of any
  field missed elsewhere.
- **Confidence:** high. The call chain is two files with a single direct hop, the source is an
  unambiguous `HttpServletRequest` parameter, and the fix uses a JDK-native API with documented
  escaping semantics. No ambiguity had to be resolved by assumption.
