## Verdict

Real LDAP injection vulnerability. The user-supplied `param` parameter is concatenated directly into the LDAP filter string without escaping LDAP metacharacters, allowing an attacker to modify the filter logic at line 59.

## Source

Line 54-55: User input from request parameter `BenchmarkTest00021` flows into the LDAP filter string construction via string concatenation.

```java
String param = request.getParameter("BenchmarkTest00021");
// ... 
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
```

An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`, null bytes) to alter filter logic. For example, `param = "*))(&(uid=*"` transforms the filter to `(&(objectclass=person))(|(uid=*))(&(uid=*)(street={0}))`, bypassing intended restrictions.

## Fix

Escape LDAP special characters in the user input before constructing the filter. Add this helper method:

```java
private static String escapeLDAPSearchFilter(String input) {
    StringBuilder output = new StringBuilder();
    for (int i = 0; i < input.length(); i++) {
        char c = input.charAt(i);
        switch (c) {
            case '*':
                output.append("\\2a");
                break;
            case '(':
                output.append("\\28");
                break;
            case ')':
                output.append("\\29");
                break;
            case '\\':
                output.append("\\5c");
                break;
            case '\0':
                output.append("\\00");
                break;
            default:
                output.append(c);
        }
    }
    return output.toString();
}
```

Then escape the parameter before use:

```java
String param = request.getParameter("BenchmarkTest00021");
if (param == null) param = "";

String escapedParam = escapeLDAPSearchFilter(param);
String filter = "(&(objectclass=person))(|(uid=" + escapedParam + ")(street={0}))";
```

## Explanation

LDAP injection occurs when untrusted input is concatenated into LDAP filter strings. LDAP filters use metacharacters like `*` (wildcard), `()` (grouping), and `\` (escape) to construct logical expressions. Without escaping, an attacker can inject additional operators to bypass authentication, authorization, or information access controls.

The fix implements RFC 4515 escaping by replacing LDAP metacharacters with their hex-encoded equivalents (`\XX` format). This preserves the literal intent of the user input while preventing injection. The escape function is applied to the attacker-controlled `param` before it enters the filter string, ensuring that any metacharacters are treated as literal characters rather than filter operators.
