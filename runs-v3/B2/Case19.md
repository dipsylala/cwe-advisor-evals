## Verdict

not_exploitable

## Source

There is no untrusted source on this path. The value that reaches the redirect is assigned as a
string literal and never derives from the request.

Path:

1. `Case19A.handle(HttpServletRequest, HttpServletResponse)` - `Case19A.java:24` assigns
   `data = "foo"`, a compile-time constant. The `request` object is in scope but is never read:
   no `getParameter`, `getHeader`, `getQueryString`, `getCookies`, or body read occurs anywhere in
   the method or the class.
2. `Case19A.java:26` passes that constant to `(new Case19B()).handleSink(data, request, response)`.
3. `Case19B.handleSink` - `Case19B.java:17` null-guards `data`, then `Case19B.java:23` parses it
   with `new URI(data)` into a local `uri` that is never used afterwards (the parse acts only as a
   syntax gate, and returns a fixed "Invalid redirect URL" response on `URISyntaxException`).
4. Sink: `Case19B.java:32` calls `response.sendRedirect(data)`.

`data` is never reassigned, never concatenated with request-derived text, and is not a field that
another code path could set - it is a local passed by value. `Case19B` is instantiated in exactly
one place, `Case19A.java:26`, so no other caller supplies a different value.

The breaking link is step 1: the redirect target is a hardcoded constant, so an attacker has no
means of influencing the `Location` header. `sendRedirect("foo")` resolves to a fixed
context-relative path on the application's own origin. Nothing attacker-controlled reaches the sink.

## Fix

No change is proposed. The reported line is not exploitable as written, and editing it would be
churn against code that has no reachable weakness.

For future maintenance: if `data` is ever changed to carry request-derived input (a `?next=` or
`?returnUrl=` parameter, a header, or a stored value that originates from a request), this line
becomes a genuine open redirect and needs a destination check before it. The check belongs on the
parsed `URI` that line 23 already produces rather than on the raw string: a URI whose
`isAbsolute()` is false and whose `getHost()` is null is a relative path and safe to redirect to,
and an absolute URI must match an exact server-side host allowlist, with the canonical allowlisted
value - not the original input - passed to `sendRedirect`. A `startsWith("/")` test is not a
substitute, since it accepts `//evil.example`, which browsers treat as protocol-relative. Best of
all is to avoid carrying a URL at all and map an opaque key to a fixed server-defined destination.

## Explanation

Nothing changed, because the trace shows the reported flow cannot be driven by an attacker. The
scanner flagged `response.sendRedirect(data)` on the strength of the sink alone - a redirect whose
argument is a variable rather than a literal - and treated `handleSink`'s `String data` parameter
as tainted because the method sits in a servlet-facing class alongside an `HttpServletRequest`.
Following the parameter back through its single caller shows it originates as the literal `"foo"`
at `Case19A.java:24`, with the request object present but unread, so the value at the sink is a
constant known at compile time. An open redirect requires attacker influence over the destination;
here the destination is fixed by the source code and resolves to a relative path on the
application's own origin. Adding allowlist validation would guard a value that cannot vary, closing
no attack path while implying to future readers that this input is untrusted. The correct outcome
is to suppress the finding with a note recording that the redirect target is a hardcoded constant,
and to re-open it if the assignment at `Case19A.java:24` is ever changed to read from the request.

## Behaviour changes

none - no code change is proposed, so the sink's contract is untouched. `sendRedirect` continues to
commit the response with a 302 and a `Location` header resolved against the request URI, continues
to throw `IllegalStateException` if the response was already committed, and the caller continues to
return immediately afterwards. The unused `URI` parse at line 23 and its `URISyntaxException`
branch are left as they are: the local `uri` is dead, but removing it is unrelated to this finding.

Assumptions (recorded per autonomous mode, not asked): the two files supplied are the complete call
chain for this finding, so `Case19A.handle` is the only entry point that reaches `handleSink`. A
repository-wide search for `Case19B` returns only its own declaration and that one call site, which
supports this. `handleSink` is nonetheless `public`, so a caller added outside this chain could pass
request-derived data and make the line exploitable; the verdict covers the reported path as it
stands today. Confidence: medium-high - the trace itself is unambiguous and requires no assumption,
with the reservation above applying only to callers that do not currently exist.
