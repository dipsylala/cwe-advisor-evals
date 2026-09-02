## Verdict

Confirmed. The servlet writes an attacker-controlled HTTP `Referer` header value directly into the response body without HTML-encoding it, allowing reflected Cross-Site Scripting.

## Source

`doPost` reads the `Referer` header from the incoming request:

```java
String param = "";
java.util.Enumeration<String> headers = request.getHeaders("Referer");

if (headers != null && headers.hasMoreElements()) {
    param = headers.nextElement(); // just grab first element
}

param = java.net.URLDecoder.decode(param, "UTF-8");
```

`Referer` is fully attacker-controlled (a client can send any value), and the code URL-decodes it, which strips out any encoding an intermediary might have applied and hands back raw characters including `<`, `>`, `"`, and `'`.

## Fix

Sink at line 57:

```java
response.getWriter().format(param, obj);
```

Here `param` is used as the *format string* passed to `Formatter.format`, and its decoded contents are written verbatim (aside from `%` conversions) into the HTML response body with `text/html` content type — so any HTML/JavaScript in the `Referer` header is reflected into the page as-is.

Replace this with an approach that (a) never treats attacker input as a format string, and (b) HTML-encodes the value before it is written into HTML output:

```java
String safeParam = org.owasp.encoder.Encode.forHtml(param);
response.getWriter().write(safeParam);
```

This uses the OWASP Encoder library (`org.owasp.encoder:encoder`) so that `<`, `>`, `&`, `"`, and `'` are converted to their HTML entity equivalents before being written, and it drops the use of the tainted string as a `Formatter` pattern entirely — the literal, encoded value is written with `write(String)` rather than being interpreted for `%` conversions.

If the two placeholder values (`"a"`, `"b"`) need to appear in the output, build the format string as a fixed, hard-coded literal owned by the application (e.g. `"%s %s"`) and pass the encoded user value only as encoded output text, not as the format pattern itself — never pass request-derived data as the first argument to `String.format`/`Formatter.format`.

## Explanation

`Formatter.format(String format, Object... args)` (and `String.format`) treat their first argument as a format pattern: everything in it that isn't a `%` conversion specifier is emitted unchanged. When that first argument comes from user input — here, the `Referer` header, explicitly URL-decoded to undo any transport-level encoding — an attacker fully controls the bytes that land in the HTTP response body. Because the response's content type is `text/html`, a `Referer` value such as `<script>alert(document.cookie)</script>` is written straight into the page and executed by the victim's browser when rendered, which is the classic reflected-XSS pattern: untrusted input flows unmodified from a request source to an HTML response sink.

The fix addresses both problems that make this exploitable: it stops using attacker-supplied text as a format string (removing any risk from `%` sequences being interpreted, and any expectation that the string is "just data"), and it output-encodes the value for the HTML context before writing it. HTML entity-encoding neutralizes the characters a browser needs to parse a tag, attribute, or script boundary (`<`, `>`, `&`, `"`, `'`), so the reflected value renders as inert text instead of being parsed as markup or script, regardless of what the client sends in the `Referer` header.
