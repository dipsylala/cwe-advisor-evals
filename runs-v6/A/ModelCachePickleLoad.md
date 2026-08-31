## Verdict

Confirmed. `pickle.loads(cached)` at line 19 deserializes bytes read straight from Redis
(`cache.get(f"model:{model_name}")`). `redis.Redis()` is constructed with no host/port/auth
arguments, i.e. the default local, unauthenticated connection, so anything able to reach that
Redis instance (or any other component sharing it) can `SET` a key under the `model:` namespace.
`pickle.loads` will execute arbitrary code embedded in whatever bytes it is given via
`__reduce__`/`__setstate__`, regardless of who wrote them, so this is a real deserialization sink
even though the intended writer is a trusted nightly batch job - the vulnerability is that nothing
on the read path verifies the bytes actually came from that job before executing them.

## Source

`cached = cache.get(f"model:{model_name}")` (line 14) - attacker-reachable because:
- `model_name` comes directly from the URL path (`/predictions/<model_name>`), so a caller
  controls which cache key is read.
- The Redis client has no authentication configured, so the value stored at that key is not
  guaranteed to have come from the batch-training job; anything with network access to Redis can
  write it.

The tainted value flows unchanged into `pickle.loads(cached)` on line 19, the deserialization sink.

## Fix

```python
import hashlib
import hmac
import io
import os
import pickle

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis()

# Shared secret used to sign model blobs when the batch-training job writes them,
# and to verify them here before deserializing. Must be provisioned out-of-band
# (e.g. secrets manager / env var), never derived from request data.
_MODEL_CACHE_HMAC_KEY = os.environ["MODEL_CACHE_HMAC_KEY"].encode()
_SIG_LEN = hashlib.sha256().digest_size

# Only classes the batch job actually needs to ship are allowed to be
# reconstructed; anything else raises instead of unpickling.
_ALLOWED_UNPICKLE_CLASSES = {
    ("sklearn.linear_model._base", "LinearRegression"),
    ("sklearn.ensemble._forest", "RandomForestClassifier"),
    ("numpy", "ndarray"),
    ("numpy.core.multiarray", "_reconstruct"),
}


class _RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in _ALLOWED_UNPICKLE_CLASSES:
            raise pickle.UnpicklingError(f"disallowed class during model load: {module}.{name}")
        return super().find_class(module, name)


def _load_trusted_model(payload: bytes):
    if payload is None or len(payload) <= _SIG_LEN:
        raise ValueError("model cache entry missing or malformed")

    signature, blob = payload[:_SIG_LEN], payload[_SIG_LEN:]
    expected = hmac.new(_MODEL_CACHE_HMAC_KEY, blob, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("model cache entry failed integrity check")

    return _RestrictedUnpickler(io.BytesIO(blob)).load()


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; the batch job must sign each blob the same way
    # this endpoint verifies it (see _load_trusted_model).
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    try:
        model = _load_trusted_model(cached)
    except (ValueError, pickle.UnpicklingError):
        return jsonify(error="model unavailable"), 503

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

The nightly batch job must be updated to match, writing `signature + blob` instead of a bare
pickle:

```python
blob = pickle.dumps(model)
signature = hmac.new(_MODEL_CACHE_HMAC_KEY, blob, hashlib.sha256).digest()
cache.set(f"model:{model_name}", signature + blob)
```

## Explanation

`pickle.loads` treats its input as executable instructions, not inert data - a crafted payload
can run arbitrary code the moment it is unpickled, so the only safe posture is to never call it on
bytes whose provenance cannot be verified. Because Redis is reached with no credentials, "written
by the batch job" was an assumption, not a guarantee enforced anywhere in this code path.

The fix adds two independent layers:

1. **Authenticity/integrity (primary defense).** An HMAC-SHA256 signature is computed over the
   pickle bytes using a secret only the batch job and this service hold, and verified with
   `hmac.compare_digest` (constant-time, avoiding timing side channels) before any deserialization
   happens. An attacker who can write to Redis but does not know the secret cannot produce a
   signature that passes, so their payload is rejected before `pickle` ever inspects it.
2. **Class allowlisting (defense-in-depth).** Even a legitimately-signed blob is restricted to a
   fixed set of expected model/array classes via a custom `Unpickler.find_class` override, so a
   compromise of the signing secret alone still cannot be used to instantiate arbitrary Python
   objects (e.g. `os.system` via `__reduce__`) - only the classes the batch job is actually
   expected to emit.

Both the signature and the allowlist are computed/checked outside of any attacker-controlled
input (`model_name` only selects which cache key is read, never the key material or the allowed
class list), so widening the URL surface cannot be used to bypass either check. `cache.get`
returning `None` and unpicking/verification failures are both handled by returning an error
response rather than propagating an exception with model internals.
