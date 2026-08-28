# CWE-117: Improper Output Neutralization for Logs - LogForgeOnFailure

## Verdict

Confirmed. `LogForgeOnFailure.java:25` writes an unvalidated request parameter into a log
record, so an attacker controls the bytes that reach the log stream.

- **Source:** `request.getParameter("user")` at line 14 - attacker-controlled, unbounded, and
  never validated or neutralized on the way to the sink.
- **Sink:** `logger.error("Login failed for " + username, e)` at line 25. The username is
  concatenated into the message, so whatever it contains becomes part of the rendered log line.
- **Impact:** A username containing `\r\n` terminates the current record early and starts a new
  one that the attacker composes in full. Because this is the *failed* login branch, it is
  reachable without any credentials - the attacker only needs to submit a bad password. A value
  such as `bob\r\n2026-08-28 10:00:00 INFO  Login succeeded for admin` forges an
  authentication-success record. That corrupts exactly the evidence an incident responder
  relies on: it can bury a real brute-force attempt in noise, frame another account, or break
  the parser feeding the SIEM. Control characters carry downstream too - ANSI escape sequences
  (`\u001b[`) execute in a terminal tailing the file, and unbalanced quotes or delimiters break
  JSON/CSV ingestion.

Line 19 has the same defect and should be fixed in the same pass. SLF4J's `{}` placeholder is a
formatting and allocation optimization - it substitutes the argument's `toString()` verbatim and
performs no neutralization whatsoever. Treating parameterized logging as a CWE-117 defence is the
most common wrong fix for this weakness; the scanner flagged line 25 only because concatenation is
the easier pattern to match, not because line 19 is safe.

## Source

`e:/Github/cwe-advisor/evals/cases/117/java/LogForgeOnFailure/LogForgeOnFailure.java`

```java
package evalcases;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogForgeOnFailure
{
    private static final Logger logger = LoggerFactory.getLogger(LogForgeOnFailure.class);

    public void handle(HttpServletRequest request, HttpServletResponse response, Authenticator authenticator)
    {
        String username = request.getParameter("user");

        try
        {
            authenticator.authenticate(username, request.getParameter("password"));
            logger.info("Login succeeded for {}", username);
            response.setStatus(HttpServletResponse.SC_OK);
        }
        catch (AuthenticationException e)
        {
            // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
            logger.error("Login failed for " + username, e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
```

## Fix

Neutralize the untrusted value immediately before it reaches the logger, and keep the
parameterized call form so the exception is still attached as a `Throwable` rather than being
flattened into the message.

```java
package evalcases;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogForgeOnFailure
{
    private static final Logger logger = LoggerFactory.getLogger(LogForgeOnFailure.class);

    /**
     * Characters that can terminate or restructure a log record: the ASCII control range
     * (CR, LF, NUL, TAB, and the ESC that begins an ANSI sequence), plus the Unicode line
     * separators that many log viewers and parsers also treat as line breaks.
     */
    private static final Pattern LOG_UNSAFE = Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");

    /** Bounds a single field so an oversized parameter cannot flood or truncate the log. */
    private static final int MAX_LOGGED_LENGTH = 64;

    public void handle(HttpServletRequest request, HttpServletResponse response, Authenticator authenticator)
    {
        String username = request.getParameter("user");

        try
        {
            authenticator.authenticate(username, request.getParameter("password"));
            logger.info("Login succeeded for {}", forLog(username));
            response.setStatus(HttpServletResponse.SC_OK);
        }
        catch (AuthenticationException e)
        {
            logger.error("Login failed for {}", forLog(username), e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * Renders an untrusted value safe to place in a log record. Replaces rather than deletes,
     * so a forgery attempt stays visible in the log instead of collapsing into something that
     * reads like a legitimate entry.
     */
    private static String forLog(String value)
    {
        if (value == null)
        {
            return "<null>";
        }

        String bounded = value.length() > MAX_LOGGED_LENGTH
                ? value.substring(0, MAX_LOGGED_LENGTH) + "...<truncated>"
                : value;

        return LOG_UNSAFE.matcher(bounded).replaceAll("_");
    }
}
```

### Defence in depth: neutralize at the appender

The helper protects the values this class passes. It does not protect a newline arriving through
`e.getMessage()`, nor one logged by any other class that handles a request parameter. Add a
layout-level filter so the guarantee holds process-wide, and keep the call-site helper as the
primary, explicit fix.

- **Logback** (`logback.xml`) - wrap the message conversion word in a replace:
  `%replace(%msg){'[\r\n]', '_'}`. Apply the same wrapper to `%ex` / `%throwable` if exception
  text can carry attacker input.
- **Log4j 2** (`log4j2.xml`) - use the encoding converter: `%enc{%m}{CRLF}` neutralizes CR and LF;
  `%enc{%m}{JSON}` is the right choice when the layout emits JSON.
- **Structured logging** is the strongest option where you can adopt it. Emitting the username as a
  discrete field of a JSON layout (Logback's `LogstashEncoder`, or Log4j 2's `JsonTemplateLayout`)
  makes the encoder responsible for escaping, and a newline inside a field value can no longer
  create a second record. Prefer this if the logs already feed a SIEM. It removes the *forgery*
  primitive, not the need to bound field length.

## Explanation

**Why this is the fix.** CWE-117 is an output-encoding weakness, so the defence belongs at the
boundary where data crosses into the log, matched to that channel's structure. Line-oriented log
files use `\n` as the record delimiter, so neutralizing the delimiter removes the attacker's ability
to author a record at all. `\p{Cntrl}` is the right character class rather than a bare `[\r\n]`: it
also strips the ESC that begins an ANSI escape sequence - what makes a `less` or `tail` session on
the log file dangerous - and the NUL that truncates the line for C-based consumers. The two Unicode
line separators are added explicitly because Java's `\p{Cntrl}` is ASCII-only by default and would
otherwise let `\u2028` through to a viewer that renders it as a break.

**Why replace rather than delete.** Substituting `_` keeps the injection attempt legible. Deleting
the characters would render `bob\r\nLogin succeeded for admin` as one plausible sentence, quietly
destroying the evidence that someone probed the endpoint.

**Why the truncation.** Neutralization alone still lets an attacker submit a megabyte username on
every failed login. Bounding the field caps log volume and stops a single record from overrunning a
downstream parser's line-length limit - a limit that, once hit, often causes the consumer to split
the record and reintroduce the forgery.

**The SLF4J argument order.** In `logger.error("Login failed for {}", forLog(username), e)` there is
one placeholder and two arguments. SLF4J treats a trailing `Throwable` in excess of the placeholder
count as the exception, so the stack trace is still recorded. This matters: writing
`logger.error("Login failed for {} {}", forLog(username), e)` would consume the exception as a
second placeholder value, call `toString()` on it, and silently discard the stack trace.

**What was deliberately left alone.** The password is read inline at line 18 and never logged, which
is correct - keep it that way. The `Authenticator` contract and the HTTP status codes are untouched;
the failure branch still returns 401 without revealing whether the username exists.

**Verification.** Submit a failed login with `user=bob%0d%0aLogin+succeeded+for+admin` and confirm
the log holds exactly one record, with the separators rendered as `_`. Repeat with an ESC-prefixed
value (`%1b%5b31m`) and confirm no colour change when tailing the file. A regression test asserting
`forLog("a\r\nb").equals("a__b")` pins the behaviour, and a second asserting the sanitized output
contains no character matching `\p{Cntrl}` keeps future edits honest.
