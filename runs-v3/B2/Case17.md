## Verdict

not_exploitable

## Source

No untrusted data reaches the sink on the reported path.

Sink: `Case17B.java:32` - `directoryContext.search("", search, null)`, where `search` is built at line 29 by concatenation: `"(cn=" + data + ")"`. The concatenation itself is the pattern a filter-injection rule flags, so the sink is correctly identified; the question is what flows into `data`.

Tracing backwards from the sink:

1. `Case17B.java:32` - `search` is passed as the filter argument.
2. `Case17B.java:29` - `search` is derived solely from the `data` parameter of `handleSink`; it is assigned once, immediately before the sink, and is not modified in between.
3. `Case17B.java:17` - `data` is a method parameter of `handleSink(String data, HttpServletRequest request, HttpServletResponse response)`. It is not reassigned anywhere in the method body, so its value at the sink is exactly the value the caller supplied.
4. `Case17A.java:18` - the only caller in this call chain: `(new Case17B()).handleSink(data, request, response)`.
5. `Case17A.java:16` - `data = "foo";` - a hardcoded string literal. It is the sole assignment to `data` in `Case17A.handle`, there is no intervening branch, loop, or reassignment between line 16 and the call at line 18, and no value is read from `request` at any point.

The breaking link is step 5. `HttpServletRequest request` is threaded through both methods but is never read - no `getParameter`, `getHeader`, `getCookies`, `getQueryString`, `getInputStream`, or any other accessor is called on it in either file, and no other request-derived value (session attribute, path info, servlet parameter) is consulted. The value that reaches the LDAP filter is the compile-time constant `"foo"`, which contains none of the LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) that would be needed to escape the `(cn=...)` term. There is no attacker-controlled input on this path, so the concatenation cannot be influenced.

One scope note, which does not change the verdict for the reported path: `handleSink` is `public` and accepts an arbitrary `String`, so its safety rests entirely on its callers rather than on anything the method enforces. Within the code under review the only caller passes a literal. If a caller is later added that passes request-derived data, line 29 becomes injectable immediately and the finding becomes live.

## Fix

No change is proposed. The reported path carries a hardcoded literal to the sink, so there is no weakness to remediate here and modifying working code would be unwarranted.

For reference, should `handleSink` ever be given caller-controlled input, the fix at line 29-32 is JNDI's parameterized search overload rather than concatenation - replace the interpolated value with a `{0}` placeholder and pass the value in the `filterArgs` array (`directoryContext.search("", "(cn={0})", new Object[] { data }, new SearchControls())`), which makes the JDK escape the argument. That overload requires an explicit `SearchControls` where the three-argument form defaults to `OBJECT_SCOPE` with all attributes returned, so any such change would have to supply controls matching the current default scope rather than silently widening it.

## Explanation

Nothing changed. The scanner flagged the string concatenation at `Case17B.java:29` feeding `DirContext.search()` at line 32, which is a genuine injection shape, but a backwards trace from the sink shows the only value that can reach it is the literal `"foo"` assigned at `Case17A.java:16`. `data` is never reassigned in either method, and the `HttpServletRequest` that would be the plausible source of untrusted data is passed down the call chain and then never read - no accessor is invoked on it at all. With no attacker-controlled input on the path and no LDAP metacharacters in the constant, the filter's structure cannot be altered, so this is a false positive arising from the concatenation pattern rather than from a reachable taint flow. The finding should be suppressed with a justification recording that the parameter is caller-supplied and currently constant, so that the suppression is revisited if a new caller passes request data.

## Behaviour changes

none - no code was modified.
