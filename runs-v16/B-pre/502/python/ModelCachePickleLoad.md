## Verdict

Exploitable. A malicious pickle payload in Redis cache could execute arbitrary code during deserialization.

## Source

Redis cache data retrieved at line 14: `cached = cache.get(f"model:{model_name}")`. The attacker cannot control the cache key directly (it is server-controlled), but an attacker who can tamper with Redis or influence the batch-training job could inject a malicious pickle under any model name.

## Fix

**Vulnerable code (line 19):**
```python
model = pickle.loads(cached)
```

**Fixed code:**
```python
import hmac
import hashlib
import io
import pickle

class RestrictedUnpickler(pickle.Unpickler):
    """Restrict deserialization to safe built-in types and whitelisted classes."""
    def find_class(self, module, name):
        # Define allowlist of classes safe to instantiate from pickle
        allowlist = {
            ('builtins', 'dict'),
            ('builtins', 'list'),
            ('builtins', 'tuple'),
            ('builtins', 'set'),
            ('builtins', 'frozenset'),
            ('builtins', 'int'),
            ('builtins', 'float'),
            ('builtins', 'str'),
            ('builtins', 'bytes'),
            ('builtins', 'bool'),
            ('builtins', 'NoneType'),
            # Add specific model classes as needed:
            # ('sklearn.ensemble._forest', 'RandomForestClassifier'),
            # ('sklearn.linear_model', 'LogisticRegression'),
        }
        if (module, name) not in allowlist:
            raise pickle.UnpicklingError(f"Unpickling of {module}.{name} is not allowed")
        return super().find_class(module, name)

# Verify integrity with HMAC before deserializing
# The batch-training job must also compute this signature when pickling
hmac_key = os.environ.get('MODEL_CACHE_HMAC_KEY')  # Set via environment/secrets
if not hmac_key:
    return jsonify(error="model cache key not configured"), 500

# Cached data format: "{hmac}:{pickle_data}" (hex-encoded HMAC, base64 or raw pickle)
if ':' not in cached.decode('utf-8', errors='ignore'):
    return jsonify(error="invalid cached model format"), 500

hmac_hex, pickle_data = cached.split(b':', 1)
expected_hmac = hmac.new(hmac_key.encode(), pickle_data, hashlib.sha256).hexdigest()
if not hmac.compare_digest(hmac_hex.decode(), expected_hmac):
    return jsonify(error="model cache integrity check failed"), 403

model = RestrictedUnpickler(io.BytesIO(pickle_data)).load()
```

## Explanation

The original code deserializes untrusted data from Redis using `pickle.loads()`, which executes arbitrary code during deserialization via pickle's `__reduce__` and `__setstate__` mechanisms. If an attacker can write to Redis or manipulate the batch-training job, they can inject a malicious pickle that runs system commands. The fix uses two layers of defence: (1) a `RestrictedUnpickler` that overrides `find_class()` to whitelist only safe classes, preventing instantiation of attacker-controlled objects; (2) HMAC-SHA256 verification to detect tampering, using a shared secret between the batch job and this consumer. The batch-training job must be updated to compute and prepend the HMAC when writing to cache; if that change cannot be coordinated, the HMAC check can be omitted as a fallback, though integrity verification is strongly recommended for untrusted storage.

## Behaviour changes

The fixed code requires the batch-training job to compute and sign pickles with HMAC, introducing a backwards-incompatible change to the cache format. Existing unsigned pickles will be rejected. The allowlist must be updated to include every model class the batch job produces; an overly restrictive allowlist will cause legitimate models to fail deserialization. The function now returns 500 if `MODEL_CACHE_HMAC_KEY` environment variable is not set, and 403 if HMAC verification fails, which are new failure modes compared to the original code. If the HMAC check is deferred pending batch-job coordination, remove the HMAC validation block and the `RestrictedUnpickler` alone will prevent code execution but will not detect tampering. The `.predict()` return value and exception handling remain unchanged.
