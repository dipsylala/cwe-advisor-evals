## Verdict
Confirmed LDAP injection at line 32 via unescaped user input in the LDAP filter string.

## Source
Case09A.java line 16: `data = request.getParameter("name");`

The user-controlled `name` parameter flows through the call chain (Case09A → Case09B → Case09C → Case09D → Case09E) to Case09E.java line 29 where it is concatenated directly into an LDAP filter.

## Fix
Escape LDAP filter metacharacters in the search filter. Replace the filter construction in Case09E.java lines 29-32:

```java
// Vulnerable code (lines 29-32):
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);

// Fixed code:
String escapedData = escapeLdapFilter(data);
String search = "(cn=" + escapedData + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

Add the LDAP filter escaping method to Case09E class:

```java
private static String escapeLdapFilter(String input) {
    if (input == null) {
        return null;
    }
    StringBuilder result = new StringBuilder();
    for (int i = 0; i < input.length(); i++) {
        char c = input.charAt(i);
        switch (c) {
            case '*':
                result.append("\\2a");
                break;
            case '(':
                result.append("\\28");
                break;
            case ')':
                result.append("\\29");
                break;
            case '\\':
                result.append("\\5c");
                break;
            case '\0':
                result.append("\\00");
                break;
            default:
                result.append(c);
        }
    }
    return result.toString();
}
```

## Explanation
LDAP filter syntax uses special characters (`*`, `(`, `)`, `\`) as metacharacters. Attackers can inject filter logic by including these characters in input. For example, `*)(|(cn=*` would transform the filter from `(cn=user*)(|(cn=*))` to bypass logic.

The fix escapes these metacharacters by replacing each with a backslash followed by the two-digit hex ASCII value (RFC 4515 format). This ensures user input is treated as literal filter value data, not as filter syntax.

The escaping is applied before constructing the filter string, preventing the injected syntax from being interpreted by the LDAP directory service.
