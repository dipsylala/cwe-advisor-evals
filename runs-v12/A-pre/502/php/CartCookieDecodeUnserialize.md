## Verdict

This code is vulnerable to CWE-502 (Deserialization of Untrusted Data). The `unserialize()` function on line 12 of `CartCookie.php` processes untrusted cookie data without restriction, allowing an attacker to instantiate arbitrary PHP objects and trigger code execution through object injection via magic methods.

## Source

**File:** `evals/cases/502/php/CartCookieDecodeUnserialize/CartCookie.php`  
**Line:** 12

```php
return unserialize($payload);
```

The cookie value flows from an untrusted request context (CartController line 9-10) directly into `unserialize()`. An attacker can craft a malicious serialized object that exploits `__wakeup()`, `__destruct()`, or other magic methods during deserialization.

## Fix

Replace `unserialize()` with `json_decode()`:

```php
<?php

final class CartCookie
{
    public static function decode(string $encoded): mixed
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false) {
            return ['items' => []];
        }

        return json_decode($payload, true) ?? ['items' => []];
    }
}
```

The encoding side (not shown in the fixture) must also change from `serialize()` to `json_encode()` to maintain consistency:

```php
// When storing: base64_encode(json_encode($cart))
// When retrieving: json_decode(base64_decode($encoded, true), true)
```

## Explanation

PHP's `unserialize()` function automatically instantiates objects during deserialization, triggering magic methods like `__wakeup()` and `__destruct()`. A malicious actor can exploit these to execute arbitrary code through object injection—a technique where attacker-controlled class instances invoke dangerous operations. Using `json_decode()` instead avoids object instantiation entirely, accepting only safe JSON primitives: strings, numbers, arrays, and objects represented as associative arrays (not class instances). This eliminates the attack surface while preserving the ability to store and retrieve structured data in cookies.
