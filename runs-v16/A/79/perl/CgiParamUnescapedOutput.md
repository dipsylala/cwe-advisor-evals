## Verdict

The code is vulnerable. Line 18 outputs user-supplied input directly into HTML without escaping.

## Source

`$cgi->param('note')` retrieves an untrusted parameter from the request. The parameter value is attacker-controlled and may contain HTML or JavaScript.

## Fix

Import `escapeHTML` from the CGI module and apply it to the output:

```perl
use CGI qw(:standard);
```

Then on line 18, replace:

```perl
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";
```

with:

```perl
print "<p>Customer note: " . escapeHTML($cgi->param('note')) . "</p>\n";
```

Alternatively, use the CGI object method directly:

```perl
print "<p>Customer note: " . CGI::Util::escape($cgi->param('note')) . "</p>\n";
```

Or:

```perl
print "<p>Customer note: " . $cgi->escape($cgi->param('note')) . "</p>\n";
```

## Explanation

The `escapeHTML()` function from CGI.pm converts dangerous HTML characters to safe entities: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, and `"` becomes `&quot;`. This prevents injected markup from being parsed as HTML.

An attacker submitting `<script>alert('xss')</script>` as the note parameter would have it rendered as literal text (`&lt;script&gt;...`) rather than executed as code.
