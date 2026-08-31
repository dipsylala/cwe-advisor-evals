## Verdict

Confirmed. `$ticket_subject` and `$customer_reply` are read directly from CGI request parameters and concatenated, unescaped, into an HTML string that is printed straight to the response body. A reply or subject value containing `<script>...</script>` or an `onerror`-bearing tag executes in the viewing agent's browser.

## Source

```perl
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');
```

(lines 12-13) — both are attacker-controlled query/form parameters with no validation or encoding applied before use.

## Fix

```perl
my $ticket_html = "<div class='ticket'>"
    . "<h2>" . $cgi->escapeHTML($ticket_subject) . "</h2>"
    . "<div class='reply'>" . $cgi->escapeHTML($customer_reply) . "</div>"
    . $status_badge
    . "</div>";
```

Encode every user-controlled value at the point it is interpolated into the HTML fragment, using `$cgi->escapeHTML()` (CGI.pm's built-in HTML entity encoder) on `$ticket_subject` and `$customer_reply`. `$status_badge` does not need encoding since it is built entirely from a fixed string literal, not from `$ticket_id` content.

If `CGI.pm`'s escaper is unavailable or the codebase is migrating off it, `HTML::Entities::encode_entities()` from the `HTML-Parser` distribution is an equivalent, actively maintained alternative — encode with it in the same place.

## Explanation

The handler builds `$ticket_html` by string concatenation instead of through any templating or auto-escaping layer, so nothing between the CGI parameter read and the `print` sink neutralizes HTML metacharacters (`<`, `>`, `"`, `'`, `&`). Both `$ticket_subject` and `$customer_reply` flow unmodified from `$cgi->param()` to the response body, so any HTML or script markup a requester supplies in the `subject` or `reply` parameters is emitted verbatim and parsed as markup by the browser rendering the ticket view — a reflected XSS.

Escaping at the point of output (rather than at the point of input) is correct here because the value is used only for HTML rendering; encoding at intake would corrupt the raw value for any other use (e.g., storage, logging) and does not compose safely if the same field is later emitted into a non-HTML context. `escapeHTML()`/`encode_entities()` convert the dangerous characters to their entity forms (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&amp;`), so injected markup renders as inert text rather than being parsed by the browser, while ordinary subject lines and replies display unchanged.
