## Verdict

not_exploitable

## Source

There is no untrusted source on the reported path.

The sink is `Case13B.java:28`:

`resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");`

The only value concatenated into the SQL string is the `data` parameter of `Case13B.handleSink(String data, HttpServletRequest request, HttpServletResponse response)`.

Tracing backwards from that parameter:

1. `Case13B.java:28` - sink. Interpolates `data`; `data` is not reassigned or transformed anywhere between the method entry (line 14) and the sink.
2. `Case13A.java:17` - the sole call site of `handleSink` in the call chain: `(new Case13B()).handleSink(data, request, response);`
3. `Case13A.java:15` - `data = "foo";` The value is a compile-time string literal. It is declared at line 12 and assigned exactly once, with no intervening branch, reassignment, or read of any external input.

`Case13A.handle` receives `HttpServletRequest request`, which is a genuine untrusted source, but it never reads from it - no `getParameter`, `getHeader`, `getCookies`, `getInputStream`, `getQueryString`, or attribute lookup appears in either file. `request` and `response` are forwarded to `handleSink` and then left unused inside it; neither reaches the query string. So the request object is present in the call chain but carries no taint into the sink.

The link that breaks the path is the assignment at `Case13A.java:15`: the value reaching the concatenation is a constant chosen by the program, not by the caller, so an attacker has no means of influencing the text of the executed statement.

## Fix

No change is proposed. The reported path cannot be exploited, and modifying the code would not close a reachable weakness.

For completeness, the flagged statement is unchanged:

```java
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

One thing worth recording rather than fixing: `handleSink` is `public`, and the concatenation would become injectable the moment any caller passes a request-derived string in place of the literal. Nothing in the current call chain does. If this method is expected to grow other callers, the durable form is a `PreparedStatement` built from the constant SQL text `select * from users where name=?` with the value supplied via `setString(1, data)` - equivalent behaviour here, and it removes the dependence on every future caller passing a safe value. That is a hardening change, not a remediation of this finding, and it is not being applied.

## Explanation

Nothing changed, because the trace shows the finding is a false positive on the reported path rather than a real injection. The scanner correctly identified a string-concatenated SQL sink at `Case13B.java:28` and correctly saw a servlet request object travelling in the same call chain, but it associated the two without establishing that request data actually reaches the concatenation. It does not: the interpolated variable is assigned the literal `"foo"` at `Case13A.java:15` and passed through unmodified, while the `HttpServletRequest` is never read in either file. Since the query text is fully determined at compile time, no input an attacker can supply can alter the statement's structure, so there is no injection to eliminate. Replacing the concatenation with a prepared statement would be safe but would close nothing on this path, and rewriting code on the strength of a finding whose trace does not hold up makes the next real finding harder to distinguish. The appropriate disposition is to record this one as not exploitable with the breaking link named - the constant assignment at `Case13A.java:15` - and to revisit it only if a caller is ever introduced that passes attacker-controlled data into `handleSink`.

## Behaviour changes

none - no code was modified.

Supporting detail for review:

- **Sink contract, unchanged:** `executeQuery` returns a `ResultSet` assigned to `resultSet`; the caller uses it only for `IO.writeLine(resultSet.getRow())` at line 30, discards the row data itself, and relies on `SQLException` propagating to the `catch` at line 32 and on the `finally` block closing `ResultSet`, `Statement`, and `Connection` in that order. Because no edit was made, all four aspects - return value, discarded output, implicit arguments, and failure behaviour - are preserved exactly.
- **Assumptions:** the two supplied files constitute the complete call chain for this finding, as stated in the report, so `Case13A.java:17` is treated as the only caller of `handleSink`. This was checked across the case directory and no other reference exists. If `Case13B` is reachable from code outside the supplied chain, that caller would need to be traced before the verdict holds for it.
- **Confidence:** high for the reported path. The chain is three steps long, fully contained in the supplied files, with a single unconditional assignment of a literal and no reassignment, aliasing, or reflection between source and sink.
