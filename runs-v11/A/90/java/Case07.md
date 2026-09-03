## Verdict
CONFIRMED - CWE-90 (LDAP Injection)

## Source
**File:** Case07B.java  
**Lines:** 29-32  

The vulnerability exists in the concatenation of unsanitized user input into an LDAP filter:
```
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

The `data` parameter originates from `request.getParameter("name")` in Case07A without any sanitization or validation. This user-controlled string is directly embedded into the LDAP search filter at line 29, then passed to `directoryContext.search()` at line 32.

## Fix
Create an LDAP filter escape utility method and apply it to the user input:

```java
private static String escapeLDAPFilter(String input) {
    if (input == null) {
        return null;
    }
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

Then modify line 29 to escape the input:
```java
String search = "(cn=" + escapeLDAPFilter(data) + ")";
```

## Explanation
LDAP filter syntax uses metacharacters such as `*` (wildcard), `(` and `)` (grouping), `&` and `|` (logical operators) to construct complex queries. When user-controlled input is concatenated directly into a filter string without escaping, an attacker can inject these metacharacters to manipulate the query logic.

For example, an attacker supplying `*` as the name parameter would transform the filter from `(cn=username)` to `(cn=*)`, which matches any entry and bypasses authentication or authorization checks.

The fix escapes all LDAP filter special characters by converting them to their hexadecimal escape sequences as defined in RFC 2254. This ensures that any user-supplied characters are treated as literal values within the filter, preventing injection attacks. The escaped input is then safe to concatenate into the filter string.
