## Verdict
Confirmed. `Case08D.handleSink` builds an LDAP search filter by directly concatenating unvalidated, unescaped user input into the filter string, allowing an attacker to inject LDAP filter metacharacters and alter the query's logic (LDAP filter injection).

## Source
`Case08A.handle` reads the tainted value from `request.getParameter("name")` and passes it unmodified through `Case08B.handleSink` and `Case08C.handleSink` to `Case08D.handleSink`.

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

            String search = "(cn=" + escapeLdapSearchFilter(data) + ")";

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
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

    /**
     * Escapes a value for safe inclusion in an LDAP search filter, per RFC 4515.
     * Each reserved filter metacharacter is replaced with its backslash-hex escape so
     * user-supplied input cannot close the "(cn=...)" clause or inject additional
     * filter terms or wildcards.
     */
    private static String escapeLdapSearchFilter(String input)
    {
        if (input == null)
        {
            return "";
        }

        StringBuilder escaped = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++)
        {
            char currentChar = input.charAt(i);
            switch (currentChar)
            {
                case '\\':
                    escaped.append("\\5c");
                    break;
                case '*':
                    escaped.append("\\2a");
                    break;
                case '(':
                    escaped.append("\\28");
                    break;
                case ')':
                    escaped.append("\\29");
                    break;
                case 0:
                    escaped.append("\\00");
                    break;
                default:
                    escaped.append(currentChar);
            }
        }
        return escaped.toString();
    }
}
```

## Explanation
The sink builds `search = "(cn=" + data + ")"` and passes it straight to `DirContext.search(name, filter, cons)`. Because `data` is the raw `name` request parameter, an attacker can supply a value such as `*)(uid=*))(|(uid=*` (or an unbalanced `)`/`(`) to close the `cn` clause early and append arbitrary additional filter terms, or use `*` to widen matches - classic LDAP filter injection (CWE-90), independent of whatever attribute or base DN the filter is later used for.

The fix adds a local `escapeLdapSearchFilter` helper that walks the tainted string and replaces each of the five characters RFC 4515 reserves in a search filter - backslash, `*`, `(`, `)`, and NUL - with its `\XX` hex escape, then uses the escaped value when building `search`. Escaping (rather than an allowlist regex) was chosen because the field being searched (`cn`) is a free-form display name that can legitimately contain most other characters (spaces, unicode, punctuation); escaping neutralizes the filter metacharacters without rejecting valid names. This is the standard LDAP filter-injection remediation and mirrors the equivalent DN-escaping approach used for LDAP distinguished names, applied here to the filter/search-string context, which is what this sink uses.

After the fix, injecting `*)(uid=*))(|(uid=*` produces the literal, inert filter `(cn=\2a\29\28uid=\2a\29\29\28|\28uid=\2a)`, which JNDI's LDAP filter parser treats as a search for the literal string rather than as filter syntax, so the attacker can no longer alter the query structure.
