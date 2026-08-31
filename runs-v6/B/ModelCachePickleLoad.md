## Verdict

- CWE-502 (Deserialization of Untrusted Data) - **exploitable**
- Location: `ModelCachePickleLoad.py:19`, sink `pickle.loads(cached)`
- Confidence: high
- Assumption: the concrete model class produced by the nightly batch-training job is unknown from this file alone (e.g. a scikit-learn estimator), so the fix below defines an explicit allowlist placeholder that the developer must populate with the real class(es) rather than guessing one.

## Source

- **Source**: `cache.get(f"model:{model_name}")` - the raw bytes stored in Redis under the `model:<name>` key. The value is written by an out-of-scope nightly batch job, but it is read back through a shared Redis instance rather than loaded directly from that job's own trusted output. Anything with write access to that Redis key space - a misconfigured ACL, a compromised neighboring service, or a future feature that writes to the same cache - can substitute an attacker-crafted pickle payload for a legitimate model. `pickle.loads` cannot distinguish a payload written by the batch job from one written by anything else with cache access, so the bytes must be treated as untrusted at the point they are deserialized.
- **Sink**: `model = pickle.loads(cached)` at line 19. `pickle.loads` executes arbitrary code via `__reduce__`/`__setstate__` during deserialization, so an attacker-supplied payload at this sink achieves remote code execution, not just a malformed model.
- Nothing between source and sink constrains or validates `cached` - it flows from `cache.get` straight into `pickle.loads` unchanged.

## Fix

Full JSON replacement (the knowledge base's primary recommendation) is not viable here without rewriting the batch-training job: the cached value is a trained model object exposing `.predict()`, not plain data, and that job is explicitly out of scope for this change. This is the "trusted-but-tampered channel" case the knowledge base calls out: the producer (the batch job) is trusted, but the transport (a shared Redis cache) is not guaranteed to be tamper-proof. The recommended fix for that case is an HMAC integrity check plus a restricted `Unpickler` that only allows constructing known model classes - both are stdlib (`pickle`, `hmac`, `hashlib`), no new dependency.

This closes the sink identified in Step 4, but it is only half the fix: the batch job (out of scope here) must be updated to prepend an HMAC-SHA256 signature over the pickled bytes, using a secret shared with this service, before writing to Redis. Without that companion change, every request will fail the signature check below. This dependency is called out explicitly rather than silently assumed.

Vulnerable code:

```python
cached = cache.get(f"model:{model_name}")
if cached is None:
    return jsonify(error="model not ready"), 404

# SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
model = pickle.loads(cached)
```

Fixed code:

```python
import hashlib
import hmac
import io
import os
import pickle

# Shared secret with the batch-training job; that job must be updated to sign
# each cached payload with the same key (see note below).
MODEL_CACHE_HMAC_KEY = os.environb[b"MODEL_CACHE_HMAC_KEY"]

# Only classes the batch-training job is actually known to emit. Populate this
# with the real model class(es) - e.g. ("sklearn.linear_model._base", "LinearRegression") -
# not a placeholder.
_ALLOWED_MODEL_CLASSES = {
    # ("<module>", "<class name>"),
}


class _RestrictedModelUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in _ALLOWED_MODEL_CLASSES:
            raise pickle.UnpicklingError(
                f"disallowed class during model unpickling: {module}.{name}"
            )
        return super().find_class(module, name)


def _load_trusted_model(payload: bytes):
    signature, serialized = payload[:32], payload[32:]
    if len(signature) != 32:
        raise ValueError("model cache entry missing HMAC signature")
    expected = hmac.new(MODEL_CACHE_HMAC_KEY, serialized, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("model cache entry failed integrity check")
    return _RestrictedModelUnpickler(io.BytesIO(serialized)).load()
```

```python
cached = cache.get(f"model:{model_name}")
if cached is None:
    return jsonify(error="model not ready"), 404

try:
    model = _load_trusted_model(cached)
except (ValueError, pickle.UnpicklingError):
    return jsonify(error="model cache entry invalid"), 502
```

## Explanation

The original code deserialized whatever bytes sat under the requested Redis key with no integrity check and no restriction on what classes could be constructed, so a poisoned cache entry would execute attacker-chosen code the moment `pickle.loads` ran. The fix adds two independent controls at the sink identified in Step 4: an HMAC-SHA256 check that rejects any payload not signed with the secret shared by the trusted producer (closing the tampering gap in the cache transport), and a restricted `Unpickler` whose `find_class` only permits constructing the specific model class(es) the batch job is known to emit (closing the arbitrary-code-execution gap even if the signature check were somehow bypassed). Both checks run before any attacker-influenced object is fully constructed, so a payload that fails either one is rejected without reaching `model.predict()`. Full JSON replacement was not used because the cached value is a trained model object, not plain data, and rewriting the batch-training pipeline to emit a JSON-reconstructible format is out of scope for this fix.

## Behaviour changes

- Requests now fail with HTTP 502 and a JSON error body when the cache entry is missing a valid signature or fails the HMAC check, where the original code would previously have raised an unhandled `UnpicklingError`/`AttributeError`/etc. and returned a generic 500. This is a direct, justified consequence of rejecting untrusted or tampered payloads instead of attempting to deserialize them.
- Only the allowlisted model class(es) can now be constructed from the cache entry; a legitimate but previously-unlisted model class will be rejected with the same 502 until added to `_ALLOWED_MODEL_CLASSES`. This is required by the fix and is not incidental - the allowlist is what prevents arbitrary class instantiation.
- New external dependency introduced by this fix: the nightly batch-training job (out of scope for this change) must be updated to prepend an HMAC-SHA256 signature, computed with the same `MODEL_CACHE_HMAC_KEY` secret, to each pickled payload before writing it to Redis. Until that companion change ships, every request against this endpoint will fail the integrity check and return 502. This is flagged rather than silently assumed, per the sink-contract check.
- No change to the success-path return value or shape: on a valid, correctly-signed, allowlisted payload, `model` is the same object `pickle.loads` would have produced, and `model.predict(features)` and the JSON response are unchanged.
