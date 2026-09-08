## Verdict

**Confirmed Vulnerability**: CWE-79 (Cross-site Scripting) at line 27.

Untrusted user input from `$ticket_subject` and `$customer_reply` (obtained via `$cgi->param()`) is concatenated directly into HTML without encoding, then printed. An attacker can inject JavaScript by submitting HTML/script payloads in the `subject` or `reply` parameters, which will execute in the helpdesk UI.

## Source

**Taint Source**: Lines 11-13
- `$ticket_subject = $cgi->param('subject')` - untrusted user input
- `$customer_reply = $cgi->param('reply')` - untrusted user input
- `$ticket_id = $cgi->param('ticket_id')` - used safely (not in output context)

**Data Flow**: User parameters → string concatenation → HTML string variable → print to output

**Sink**: Line 27 (`print $ticket_html;`) outputs raw HTML containing unencoded user data

**Sink Contract**:
- The `print` statement outputs raw strings to STDOUT with no automatic encoding
- The original code does not encode or escape the input before printing
- No Content-Security-Policy or other mitigations are present

## Fix

### File: ManualHtmlConstructionPerl.pl

```perl
#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use HTML::Entities;

# Renders a single support ticket, including its subject line and the
# latest customer reply, as a small HTML fragment for the helpdesk UI.

my $cgi = CGI->new;

my $ticket_id      = $cgi->param('ticket_id');
my $ticket_subject = $cgi->param('subject');
my $customer_reply = $cgi->param('reply');

print $cgi->header('text/html');
print "<html><head><title>Ticket View</title></head><body>\n";

my $status_badge = build_status_badge($ticket_id);

my $ticket_html = "<div class='ticket'>"
    . "<h2>" . encode_entities($ticket_subject) . "</h2>"
    . "<div class='reply'>" . encode_entities($customer_reply) . "</div>"
    . $status_badge
    . "</div>";

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
print $ticket_html;

print "</body></html>\n";

sub build_status_badge {
    my ($id) = @_;
    return "<span class='badge'>Open</span>" if defined $id;
    return "<span class='badge'>Unknown</span>";
}
```

## Explanation

The fix adds `use HTML::Entities;` and wraps both untrusted variables with `encode_entities()` at lines 21 and 22 where they are inserted into HTML strings. The `encode_entities()` function (from the standard CPAN HTML::Entities module) escapes the following characters to their HTML entity equivalents: `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`, `'` → `&#39;`. This transformation ensures that any user input is treated as literal text data, not as executable HTML/JavaScript code.

For example, an attacker's payload `<script>alert(1)</script>` becomes `&lt;script&gt;alert(1)&lt;/script&gt;` in the output, which the browser renders as plain text inside the `<h2>` or `<div>` tag, not as executable code.

The `build_status_badge()` function is not modified because it does not use user input; `$ticket_id` is only checked for definedness, not rendered into HTML.

## Behaviour changes

**Output change**: User input containing HTML metacharacters (`<`, `>`, `&`, `"`, `'`) will now display those characters literally in the page (as escaped entity references) rather than being interpreted as HTML tags or attributes. This is the intended security fix.

**Example transformation**:
- **Input**: `subject=Welcome! <b>Bold text</b>`
- **Old output**: `<h2>Welcome! <b>Bold text</b></h2>` (browser renders "Welcome! **Bold text**")
- **New output**: `<h2>Welcome! &lt;b&gt;Bold text&lt;/b&gt;</h2>` (browser renders "Welcome! <b>Bold text</b>" as text)

**Legitimate use unaffected**: User input that does not contain HTML metacharacters displays identically (e.g., plain subject lines, customer names, standard text). User input containing ampersands (e.g., "Smith & Sons") will be escaped to `Smith &amp; Sons` but displays correctly.

**No functional regression**: The application's logic, status badge rendering, and page structure are preserved. The fix closes only the injection vector.
