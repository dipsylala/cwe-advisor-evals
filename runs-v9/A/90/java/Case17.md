## Verdict

False positive for the traced call chain, but the sink pattern is unsafe by construction and is fixed defensively below.

`Case17B.handleSink`'s parameter `data` reaches `directoryContext.search()` unescaped, so the sink itself is a genuine LDAP injection pattern. However, the only caller in this chain, `Case17A.handle`, assigns `data` from the fixed literal `"foo"` (never from `request`) before invoking `handleSink`. No attacker-controlled value reaches line 32 through this path, so the finding is not currently exploitable as traced. `handleSink` still accepts an `HttpServletRequest`, so it is clearly intended to eventually be driven by request data - the fix below hardens the sink regardless of caller.

## Source

- `Case17A.handle` (line 16): `data = "foo";` - a hardcoded constant, not derived from `request`.
- `Case17A.handle` (line 18): `(new Case17B()).handleSink(data, request, response);` - passes the constant into the sink method.
- `Case17B.handleSink` (line 29): `String search = "(cn=" + data + ")";` - builds the LDAP filter by direct string concatenation.
- `Case17B.handleSink` (line 32): `directoryContext.search("", search, null);` - the reported sink; the filter string is used as-is with no escaping.

## Fix

```java
String search = "(cn={0})";
Object[] filterArgs = new Object[] { data };

NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, null);
```

Replace the concatenated filter string and the 3-argument `search(String, String, SearchControls)` call with the 4-argument `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload. Use a positional placeholder (`{0}`) in the filter expression instead of splicing `data` in directly, and pass the value through `filterArgs`.

## Explanation

`DirContext.search`'s `filterArgs` overload substitutes each `{n}` placeholder with the corresponding element of `filterArgs` and escapes any LDAP filter metacharacters in that value per RFC 4515 (`*`, `(`, `)`, `\`, NUL) before substitution. This keeps the filter's logical structure fixed regardless of what the value contains, so a value like `*)(uid=*))(|(uid=*` can no longer close the `(cn=...)` clause early and append attacker-controlled filter terms - it is matched literally as part of the `cn` value instead. Concatenating `data` directly into `search`, as the original code does, gives no such guarantee: any metacharacter in `data` is interpreted as filter syntax by the LDAP server.

Applying this fix here is defense-in-depth rather than a response to live exploitation: in the current chain `data` is always the literal `"foo"`, which contains no filter metacharacters, so the search behaves identically before and after the change. The value is worth making regardless, because `handleSink` is written to take request context as a parameter and nothing in its signature or body prevents a future or alternate caller from passing `request`-derived data into `data` - at that point the parameterized filter is what keeps the sink safe, with no further change needed at the sink itself.
