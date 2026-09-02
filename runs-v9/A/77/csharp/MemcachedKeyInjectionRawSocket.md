## Verdict

Confirmed. `StoreProfileSnapshot` builds a raw memcached text-protocol command by directly
concatenating an attacker-influenced `cacheKey` into the command string, then writes that
string straight to the memcached socket. Memcached's text protocol treats spaces as field
delimiters and CRLF (`\r\n`) as the command terminator, so this is command injection into the
memcached protocol interpreter (CWE-77): a key containing a space, `\r`, or `\n` lets an
attacker terminate the intended `set` command early and smuggle additional memcached commands
(for example an extra `set`/`delete`/`flush_all`) onto the same connection, or corrupt the
`bytes` field so the following data is misparsed.

## Source

`cacheKey` — parameter of `ProfileCacheWriter.StoreProfileSnapshot`, documented as originating
from an upstream request header identifying the profile being refreshed (`"profile:" +
tenantSlug`). It reaches the sink unvalidated.

## Fix

```csharp
using System;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace CacheGateway
{
    public class ProfileCacheWriter
    {
        // Memcached text-protocol keys may not contain whitespace or control
        // characters (the protocol uses spaces as field delimiters and CRLF
        // as the command terminator), and are capped at 250 bytes.
        private static readonly Regex ValidKeyPattern =
            new Regex(@"^[\x21-\x7E]{1,250}$", RegexOptions.Compiled);

        private readonly Socket _memcachedSocket;

        public ProfileCacheWriter(Socket memcachedSocket)
        {
            _memcachedSocket = memcachedSocket;
        }

        // cacheKey originates from an upstream request header identifying the
        // profile being refreshed, e.g. "profile:" + tenantSlug.
        public void StoreProfileSnapshot(string cacheKey, string profileJson)
        {
            if (cacheKey == null || !ValidKeyPattern.IsMatch(cacheKey))
            {
                throw new ArgumentException(
                    "cacheKey must be 1-250 printable, non-whitespace ASCII characters.",
                    nameof(cacheKey));
            }

            byte[] value = Encoding.ASCII.GetBytes(profileJson);
            string command = "set " + cacheKey + " 0 0 " + value.Length +
                "\r\n" + profileJson + "\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(command);

            _memcachedSocket.Send(payload);
        }
    }
}
```

## Explanation

The fix rejects any `cacheKey` that is not composed entirely of printable, non-whitespace ASCII
characters (`0x21`-`0x7E`) within memcached's 250-byte key limit, before it is ever placed into
the command string. This structurally excludes the characters that matter for this sink: a
space would be read as a field delimiter (letting an attacker inject bogus flags/exptime/bytes
values into the same command), and `\r` or `\n` would terminate the `set` command early and let
an attacker append arbitrary additional memcached commands that the server would execute on the
same connection. Allowlisting valid key characters is preferred over stripping or escaping
because memcached's text protocol has no escape mechanism for its own delimiters - a stripped
key silently becomes a different (still valid) key, whereas rejecting the malformed input keeps
the failure visible at the boundary instead of allowing a subtly wrong cache entry through.
Because the check runs before `command` is built, the underlying `Send` call and existing
protocol formatting are unchanged; only genuinely malformed keys are now rejected, and no
legitimate key of the documented form (`"profile:" + tenantSlug`) is affected as long as
`tenantSlug` doesn't itself contain whitespace or control characters.
