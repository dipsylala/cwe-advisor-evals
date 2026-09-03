## Verdict

Exploitable. User-controlled data from the HTTP Referer header flows directly to the response body without output encoding, allowing XSS injection.

## Source

**Entry point**: `request.getHeaders("Referer")` (line 45)
- Retrieves the Referer HTTP header, which is attacker-controlled
- The first element is extracted via `headers.nextElement()` (line 48)
- URL-decoded via `java.net.URLDecoder.decode()` (line 52)
- URL decoding does not provide XSS protection; it only reverses percent-encoding

**Tainted variable**: `param` after line 52

## Fix

**Vulnerable code:**
```java
response.getWriter().format(param, obj);
```

**Fixed code:**
```java
response.getWriter().print(org.owasp.encoder.Encode.forHtml(param));
```

**Library recommendation**: Add OWASP Java Encoder dependency (`org.owasp.encoder:encoder`) to your project. The guidance does not specify a minimum safe version; confirm the version against current advisories before merging.

## Explanation

The fix replaces `format()` with `print()` and applies HTML entity encoding using OWASP Java Encoder's `Encode.forHtml()` method. This method escapes all HTML metacharacters in the user-supplied Referer header—converting `<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`, and quotes to entity equivalents—so they are rendered as literal text in the HTML response rather than interpreted as markup or script tags. The browser receives the encoded characters and displays them harmlessly, breaking the XSS chain.

## Behaviour changes

**Removal of format specifier interpretation**: The original code uses `format(String, Object... args)`, which interprets the first argument as a printf-style format string (e.g., `%s`, `%x`). The fixed code replaces this with `print()`, so any format specifiers in `param` are now printed as literal text after HTML encoding, not interpreted as format directives. This is a necessary change: format specifiers in user-controlled input would represent a format string vulnerability (CWE-134) in addition to the XSS risk, and the correct behavior when outputting untrusted user data is to treat it as text, not as a format string.

**Unused obj array removed from sink call**: The `obj` array passed to `format()` is no longer used. This array appeared to serve no functional purpose in the original code (it contained only `{"a", "b"}` and was never referenced in the format string). Removal of the array reference does not alter the application's behavior.

**Dependency addition**: OWASP Java Encoder must be added as a compile-time dependency if not already present.
