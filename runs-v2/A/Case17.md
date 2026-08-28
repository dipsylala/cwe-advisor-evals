## Verdict
not_exploitable

## Source
There is no untrusted source on this chain. `Case17A.java` line 16 assigns a hard-coded literal, `data = "foo"`, and passes it to `(new Case17B()).handleSink(data, request, response)` at line 18. The `HttpServletRequest` is carried along as a parameter but is never read: `Case17B.handleSink` uses only `data` when it builds `String search = "(cn=" + data + ")"` at line 29 and calls the reported sink `directoryContext.search("", search, null)` at line 32. The filter is therefore always the constant `(cn=foo)`. Separately, `Case17A.handle` is declared `private`, so it does not override any servlet dispatch method and is not reachable from outside the class at all.

## Fix
```java
none - no change required
```

## Explanation
The scanner flagged the concatenation into an LDAP filter without resolving where `data` originates, and tracing the chain shows the value is a compile-time constant rather than request-controlled input. The only variable in the filter, `data`, is fixed to `"foo"` in the caller, and no request parameter, header, cookie, or other external input is read anywhere along the path even though the request object is threaded through the call - so the filter string is invariant and no attacker can influence its syntax. The reachability picture reinforces this: `Case17A.handle` has `private` visibility and consequently cannot override the inherited servlet handler, leaving the sink with no external entry point at all. This is a false positive arising from the sink pattern rather than the data flow, and changing the code would add no security benefit. It should be closed as not exploitable, with the caveat that if `data` is ever changed to draw from request input the finding becomes a genuine CWE-90 issue and the filter should then be rebuilt using the parameterised `DirContext.search(String, String, Object[], SearchControls)` overload.
