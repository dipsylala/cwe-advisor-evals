## Verdict

Confirmed CWE-90 (LDAP Injection). Untrusted user input flows from the HTTP request parameter directly into an LDAP search filter without escaping, allowing an attacker to manipulate the query logic.

## Source

Case07A.java, line 16: `data = request.getParameter("name");`

The user-controlled `name` parameter is extracted from the HTTP request without validation.

## Fix

In Case07B.java, escape the user input before constructing the LDAP filter. Replace line 29:

```java
String search = "(cn=" + data + ")";
```

with:

```java
String search = "(cn=" + escapeLDAPSearchFilter(data) + ")";
```

Add the escaping utility method to Case07B:

```java
private static String escapeLDAPSearchFilter(String input) {
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '*':
                sb.append("\\2a");
                break;
            case '(':
                sb.append("\\28");
                break;
            case ')':
                sb.append("\\29");
                break;
            case '\\':
                sb.append("\\5c");
                break;
            case '/':
                sb.append("\\2f");
                break;
            case '\0':
                sb.append("\\00");
                break;
            default:
                sb.append(c);
        }
    }
    return sb.toString();
}
```

## Explanation

LDAP filter strings use metacharacters (`*`, `(`, `)`, `\`, `/`, NUL) to control query logic. Without escaping these characters per RFC 4515, an attacker can inject filter syntax to bypass intended query constraints or extract unintended directory data.

The call chain flows: HTTP parameter → Case07A.handleSink() → Case07B.handleSink() → directoryContext.search(). The sink at line 32 passes the unsanitized filter string to the LDAP directory search.

Escaping converts special characters to their hex-encoded form (`\XX` notation), rendering them literal values rather than operators. For example, an attacker input of `*)(cn=*` becomes `*\29\28cn=*`, which no longer matches the filter logic but is treated as a literal search value for the common name.
