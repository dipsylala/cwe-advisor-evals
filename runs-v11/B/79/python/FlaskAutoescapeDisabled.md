## Verdict

VULNERABLE: CWE-79 confirmed. User-controlled input from `request.args.get("label", "Ticket")` is marked as safe using `Markup()` on line 20 without any sanitization, allowing arbitrary HTML/JavaScript injection into the rendered response.

## Source

**File:** FlaskAutoescapeDisabled.py  
**Lines:** 14-24

Data flow:
- Line 14: `label = request.args.get("label", "Ticket")` — attacker-controlled input
- Line 20: `safe_label = Markup(label)` — marks untrusted data as safe, disabling escaping
- Line 21: Embedded in banner HTML via f-string
- Line 24: Returned as HTTP response body — sink where XSS executes in browser

## Fix

**Remove the markupsafe import and replace `Markup()` with `html.escape()`:**

```python
from flask import Flask, request
import html

app = Flask(__name__)


def lookup_ticket_status(ticket_id):
    # Stubbed lookup for the purposes of this example.
    return "open"


@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    # The caller-supplied label is HTML-escaped so it renders safely
    # when embedded in the banner without Jinja2 escaping.
    safe_label = html.escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

The vulnerability is on line 20 where `Markup(label)` marks untrusted user input as safe, completely disabling HTML escaping. This allows an attacker to inject arbitrary HTML/JavaScript by passing a payload like `<img src=x onerror=alert('XSS')>` in the `label` parameter.

The fix replaces `Markup()` with `html.escape()`, which converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures user input is treated as literal text content, not executable code, while preserving legitimate characters. The f-string embedding works unchanged because `html.escape()` returns a plain string with safe content.

## Behaviour changes

- **Before:** `label` parameter value `<img src=x onerror=alert('XSS')>` renders as executable HTML, triggering the JavaScript alert.
- **After:** The same payload renders as literal text `&lt;img src=x onerror=alert(&#x27;XSS&#x27;)&gt;` displayed to the user.
- **Legitimate input:** User labels containing `<`, `>`, or `&` characters (e.g., "A < B") now display correctly as text instead of being interpreted as HTML.
- **No functional regression:** The banner structure and styling remain intact; only dangerous metacharacters are neutralized.
