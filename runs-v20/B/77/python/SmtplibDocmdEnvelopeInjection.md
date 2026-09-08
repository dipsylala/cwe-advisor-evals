## Verdict

exploitable (confidence: high)

- cwe_id: CWE-77 (Improper Neutralization of Special Elements used in a Command / Command Injection)
- location: `SmtplibDocmdEnvelopeInjection.py`, line 19 (`smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")`)

## Source

`request.form.get("failed_sender", "")` (line 12) - an attacker-controlled field posted by the upstream relay's bounce webhook. The same taint pattern also reaches `request.form.get("notify_to", "")` (line 13), used identically at line 21.

## Fix

### File: SmtplibDocmdEnvelopeInjection.py

```python
"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import re
import smtplib

# Matches a bare RFC 5321 dot-atom mailbox address, or an empty string (the
# null reverse-path used when no sender is known). Anchored with fullmatch
# rather than ^...$ so no CR/LF, space, '<', '>', or other trailing content
# can smuggle extra SMTP command parameters past the check.
_ADDR_RE = re.compile(
    r"(?:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)?"
)


def _validate_envelope_address(value, field_name):
    """Return value unchanged if it is a bare mailbox address (or empty).

    Raises ValueError otherwise, so a malformed value is rejected before it
    is ever assembled into an SMTP command line.
    """
    if not _ADDR_RE.fullmatch(value):
        raise ValueError(f"invalid {field_name} address: {value!r}")
    return value


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using raw SMTP envelope commands.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM command so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = _validate_envelope_address(
        request.form.get("failed_sender", ""), "failed_sender")
    notify_address = _validate_envelope_address(
        request.form.get("notify_to", ""), "notify_to")

    smtp = smtplib.SMTP("relay.internal.example.com")
    smtp.docmd("EHLO", "bounce-notifier.example.com")

    smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")

    smtp.docmd("RCPT", "TO:<" + notify_address + ">")
    smtp.docmd("DATA", "")
    smtp.send(b"Subject: Delivery Failure Notice\r\n\r\n"
              b"Your message could not be delivered.\r\n.\r\n")
    smtp.quit()
    return "OK"
```

## Explanation

`failed_sender` was concatenated directly into the argument of `smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")`, an SMTP protocol client sink named in the CWE-77 Python guidance. Modern CPython (3.6.15/3.7.12/3.8.12/3.9.7/3.10+) makes `putcmd()` - which `docmd()` calls internally - reject any command line containing a bare CR or LF, but that check does not stop same-line parameter injection: a value such as `attacker@example.com> SIZE=99999999999 BODY=8BITMIME` needs no newline, only a `>` and a space, to close the address early and append extra ESMTP `MAIL` parameters or malformed trailing text to the same command. `smtplib`'s own high-level helpers (`mail()`/`rcpt()`, and by extension `sendmail()`) do not reliably close this either: they route the value through `quoteaddr()`, which calls `email.utils.parseaddr()` and, whenever that parser fails to extract a clean address (which it does for exactly these payloads, returning `('', '')`), falls back to wrapping the raw, still-malicious string in `<...>` unchanged - confirmed by running `smtplib.quoteaddr()` against the payloads above.

The fix instead validates `failed_sender` and `notify_address` against a strict, fully-anchored RFC 5321 dot-atom mailbox pattern (or an empty string, preserving the existing behaviour when a field is missing) before either value is used to build a command, per the CWE-77 root guidance's direction to allowlist the expected format where the protocol defines the value's shape, and to anchor with `re.fullmatch()` rather than `^...$` (which in Python's `re` permits a trailing newline past the `$`). The character classes in the pattern structurally exclude CR, LF, space, `<`, `>`, and every other character an attacker would need to break out of the `<...>` wrapper or append extra command parameters, so a malformed value raises `ValueError` and never reaches `docmd()`. `notify_address` (line 21) uses the identical concatenation-into-`docmd()` pattern from the same untrusted request and was validated the same way rather than left with a live twin of the reported finding in the same function.

## Behaviour changes

- A `failed_sender` or `notify_to` value that is not a bare RFC 5321 mailbox address (and not empty) now raises `ValueError` instead of being forwarded into the SMTP session; the request handler has no existing try/except around this code, so the exception propagates to the caller in the same way a `putcmd()` `ValueError` (e.g. from an embedded CR/LF) already could before this change. This is the intended fail-closed behaviour of the added check, not a side effect - reject the value here rather than let the server react unpredictably to it.
- No change to `docmd()`'s arguments, return-value handling, or the `EHLO`/`MAIL`/`RCPT`/`DATA`/`send`/`quit` call sequence; all response codes remain discarded exactly as in the original code, since that is unrelated to the injection.
- `notify_address` (line 21) received the same validation as `failed_sender` even though the reported finding cited only line 19, because it is the same sink pattern fed by the same untrusted request in the same function - see Explanation.

## Verification

- Ran `python -m py_compile` (CPython 3.13.12) against the fixed file in a scratch location: succeeded with no errors.
- Imported the fixed module standalone and exercised `_validate_envelope_address()` directly: a legitimate address (`user@example.com`) and the empty-string default both pass; the payloads `attacker@example.com> SIZE=99999999999 BODY=8BITMIME`, `a@b.com SIZE=999`, `a@b.com\r\nRCPT TO:<victim@evil.com>`, `a@b.com>`, and `<a@b.com>` are all rejected with `ValueError`.
- Confirmed against the installed CPython 3.13.12 standard library (via `inspect.getsource`) that `smtplib.SMTP.putcmd()` raises `ValueError` on embedded CR/LF but that `mail()`/`rcpt()`'s use of `quoteaddr()`/`email.utils.parseaddr()` does not neutralize the same-line parameter-injection payloads above, which is why validation is applied ahead of `docmd()` rather than relying on `smtplib`'s own address helpers.
- Every name introduced by the fix (`re`, `re.compile`, `re.Pattern.fullmatch`) is Python's standard-library `re` module already documented in CPython; no new third-party dependency was added.

## Assumptions

- Treated `failed_sender` and `notify_to` as required to be bare RFC 5321 addr-spec mailboxes (no display name, no comment, no folding whitespace) since the code only ever uses them as the content of `<...>` in a `MAIL`/`RCPT` command; this is a data-flow inference, not stated in the guidance.
- Preserved the empty-string case as valid input (matching `request.form.get(field, "")`'s existing default and the SMTP null reverse-path convention) rather than rejecting a missing field outright, to avoid a behaviour change unrelated to the injection.
- Extended the fix to `notify_address` (line 21) beyond the single reported line, per Behaviour changes above; no human was available to confirm this scope extension.
