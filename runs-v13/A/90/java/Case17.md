## Verdict
The LDAP filter at line 32 is constructed by concatenating unsanitized user input (`data`) directly into the search filter string. An attacker can inject LDAP metacharacters (such as `*`, `(`, `)`) to modify the filter logic and bypass intended constraints or retrieve unintended results.

## Source
```java
String data;
// data comes from user input via HTTP request parameter

data = "foo";

(new Case17B()).handleSink(data, request, response);
```

In Case17B.java, the unsanitized `data` is used directly:
```java
String search = "(cn=" + data + ")";
// If data = "*)(&(cn=*", search becomes "(cn=*)(&(cn=*))"
// This changes the filter logic entirely

NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

## Fix
Escape LDAP metacharacters in the filter string before using it:

```java
private static String escapeLdapFilter(String filter) {
    if (filter == null) {
        return null;
    }
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < filter.length(); i++) {
        char c = filter.charAt(i);
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

Apply it at line 29:
```java
String search = "(cn=" + escapeLdapFilter(data) + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

## Explanation
LDAP filter syntax uses special characters (`*`, `(`, `)`, `\`, `/`) that have metacharacter meaning. Without escaping, an attacker can inject filter logic by supplying values like `*)(uid=*` to transform the filter structure. Escaping these characters to their octal hex equivalents (e.g., `\2a` for `*`) renders them literal values within the filter string, neutralizing injection.

The escaping function intercepts each dangerous character and replaces it before the filter is passed to `directoryContext.search()`, ensuring the filter always matches the intended structure regardless of user input.
