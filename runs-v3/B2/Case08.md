# Case08 - CWE-90 (LDAP Injection)

## Verdict

exploitable

## Source

Untrusted data enters at `Case08A.handle()` (`Case08A.java:16`) as `request.getParameter("name")` - a fully attacker-controlled HTTP request parameter with no validation, filtering, or length restriction applied at any point.

Path to the sink:

1. `Case08A.java:16` - `data = request.getParameter("name");`
2. `Case08A.java:18` - passed unchanged to `Case08B.handleSink(data, request, response)`
3. `Case08B.java:13` - passed unchanged to `Case08C.handleSink(data, request, response)`
4. `Case08C.java:13` - passed unchanged to `Case08D.handleSink(data, request, response)`
5. `Case08D.java:29` - concatenated into an LDAP search filter: `String search = "(cn=" + data + ")";`
6. `Case08D.java:32` - sink: `directoryContext.search("", search, null)`

No node in the chain sanitises, escapes, or validates the value; it reaches the filter string verbatim. Because the filter is parsed as an expression tree, a value such as `*)(objectClass=*` closes the `cn` term and opens an attacker-chosen one, and a bare `*` converts the equality test into a match-everything wildcard. The result set is then fully disclosed to the caller by the loop at lines 33-47, which writes every attribute of every match, so a successful injection is directly observable and exfiltrates directory contents.

Sink contract as it stands today:

- **Returns** - a `NamingEnumeration<SearchResult>`; the caller iterates it and writes every attribute value of every result via `IO.writeLine`.
- **Discards** - nothing; all attributes of all matches are already surfaced.
- **Implicit arguments** - base name `""` (search relative to the provider URL's root) and `SearchControls` of `null`, which JNDI documents as equivalent to `new SearchControls()`: `ONELEVEL_SCOPE`, all attributes returned, no count or time limit.
- **Failure behaviour** - `NamingException` is caught and logged at `WARNING`; the `finally` block closes the `DirContext`.

## Fix

Only the filter construction and the search call change; the surrounding context setup, result loop, exception handling, and cleanup are untouched.

Vulnerable code (`Case08D.java:29-32`):

```java
            String search = "(cn=" + data + ")";

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

Fixed code:

```java
            String search = "(cn={0})";

            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[] { data }, null);
```

Complete fixed file (`Case08D.java`):

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

No new dependency is required. The parameterized overload is part of `javax.naming.directory.DirContext` in the JDK, so no library version change or SCA follow-up applies to this fix.

Secondary hardening, outside the minimal diff: the bind used here is anonymous against the provider URL's root with a one-level scope, so the account that executes the search should be read-only and scoped to the branch that actually holds user entries. That limits the reach of any filter field missed elsewhere, but it is not a substitute for the change above.

## Explanation

The filter is now a fixed expression, `(cn={0})`, and the untrusted value travels to the directory as a separate argument through the `filterArgs` parameter of `DirContext.search(String, String, Object[], SearchControls)`. JNDI escapes each argument for the filter grammar before substituting it, so `*`, `(`, `)`, backslash, and NUL are carried as literal characters in a string-equality comparison rather than as filter syntax. That removes the injection point structurally instead of relying on a hand-written escape or a denylist: the query's shape is decided by the program and can no longer be altered by the request, so payloads like `*)(objectClass=*` or `*)(uid=*))(|(uid=*` become an ordinary search for a `cn` that literally contains those characters, which matches nothing. Base name `""` and the `null` `SearchControls` are passed through unchanged so the search scope and returned-attribute set stay exactly as before - widening either while fixing the filter would trade an injection for a broader disclosure.

## Behaviour changes

- **Wildcard input no longer matches broadly.** Previously a `name` parameter of `jo*` reached the directory as the filter `(cn=jo*)` and prefix-matched. It is now escaped to `\2a` and matches only a `cn` whose literal value is `jo*`. This is the weakness being closed rather than an incidental change, but it is a user-visible difference if any caller was relying on wildcard search. Restoring an intentional wildcard feature would mean validating the input against an allowlist and building the pattern server-side, not passing the raw value back into the filter.
- **Filter-syntax input no longer raises a parse error.** Input containing unbalanced parentheses previously produced a malformed filter and an `InvalidSearchFilterException` (a `NamingException` subclass) that was caught and logged at `WARNING`. That input now escapes cleanly and produces an ordinary empty result set, so the warning no longer appears for those requests. Nothing branches on it - the `catch` only logs - so no control flow depends on the difference.
- **Everything else unchanged.** Base name `""`, `SearchControls` left `null` (JNDI's documented default: `ONELEVEL_SCOPE`, all attributes, no count or time limit), the returned `NamingEnumeration` and the loop that writes every attribute value, the `NamingException` catch-and-log, and the `finally` close of the `DirContext` are all identical. No argument was supplied where the original left a default, no output was added, and nothing the original discarded is now surfaced.

## Assumptions

- The finding names line 32 as the sink, and the filter is assembled one line earlier at line 29; the fix necessarily spans both lines because the sink cannot be made safe without changing the filter string it consumes.
- No LDAP schema or directory content is available, so the fix preserves the existing `cn` equality search rather than narrowing the base DN or the returned attribute set, either of which would need knowledge of the deployed directory.
- Confidence: high. The taint path is a direct four-hop pass-through with no branching, and the remediation uses a JDK-native parameterized API with no added dependency.
