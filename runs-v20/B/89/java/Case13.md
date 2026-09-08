## Verdict

- **cwe_id**: CWE-89 (SQL Injection)
- **location**: `Case13B.java`, line 28 (`sqlStatement.executeQuery("select * from users where name='"+data+"'")`)
- **verdict**: not_exploitable
- **confidence**: high

## Source

The call chain is `Case13A.handle(HttpServletRequest, HttpServletResponse)` -> `Case13B.handleSink(String data, HttpServletRequest, HttpServletResponse)`.

In `Case13A.handle`, the `data` value that is forwarded to the sink is never derived from `request`:

```
String data;
data = "foo";
(new Case13B()).handleSink(data, request, response);
```

`data` is assigned the fixed string literal `"foo"` and `request` is not read anywhere in `handle` (no `getParameter`, header, cookie, or body access). `handleSink` then concatenates that same `data` value directly into the SQL string at line 28. Because the value reaching the sink is a hard-coded literal rather than attacker-controlled input, there is no tainted data flowing from an external source to the query.

## Fix

No fix is proposed. The reported sink (string-concatenated `executeQuery`) is a SQL-injection-shaped pattern and would be exploitable if `data` ever carried external input, but on the only call path in this case directory the argument is fixed at compile time. There is no source-to-sink path for untrusted data, so no code change is warranted for this finding as reported.

## Explanation

The breaking link is the assignment `data = "foo";` in `Case13A.handle`: it replaces any potential taint from `request` with a constant before `data` is passed to `Case13B.handleSink`. The SAST tool flagged the sink pattern (string concatenation into `executeQuery`) correctly as a dangerous construct in isolation, but the data-flow trace from the only caller in this case shows the value never originates from `HttpServletRequest` or any other external source - it is a literal defined in the same method that discards `request` entirely. Since CWE-89 requires untrusted input to reach the sink, and no such input reaches it here, the finding does not represent an exploitable condition in this call chain.

## Behaviour changes

none - no code was modified.
