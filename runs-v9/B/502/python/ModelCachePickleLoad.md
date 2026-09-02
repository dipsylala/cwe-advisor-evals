## Verdict

CWE-502 (Deserialization of Untrusted Data), confirmed exploitable at `ModelCachePickleLoad.py:19`. Confidence: medium - the vulnerable mechanism (`pickle.loads()` on a value pulled from an external cache) is unambiguous; confidence is not "high" only because the exact attacker path into Redis (shared instance, network exposure, or a separate write primitive) is outside this file and assumed rather than observed.

## Source

- **Source**: the byte string returned by `cache.get(f"model:{model_name}")` (line 14) - a value read from Redis, an external, shared store.
- **Sink**: `pickle.loads(cached)` (line 19).
- **Data flow**: `model_name` comes from the URL path and only selects which cache key is read; it does not by itself inject data. The actual payload at that key is asserted by a code comment to be written nightly by a trusted batch-training job, but the deserializer has no way to verify that at runtime - anything able to write to that Redis key (a compromised job, a shared/multi-tenant cache instance, or any other service or credential-leak path with `SET` access) can substitute a malicious pickle payload, and `pickle.loads()` will execute arbitrary code via `__reduce__`/`__setstate__` on load, before `model.predict()` is ever reached. The trust boundary is the cache channel, not the intended producer, so the value must be treated as untrusted at the point it is deserialized.
- **Sink contract**: `pickle.loads()` returns a fully reconstructed Python object (here, expected to be a fitted model with `.predict()`); it discards nothing; it takes no format/whitelist arguments (fully implicit trust in the byte stream); on malformed input it raises `pickle.UnpicklingError` or similar, which is currently unhandled and would surface as an unhandled 500.

## Fix

This is the "trusted producer, untrusted channel" case the knowledge base treats as a last resort rather than the general answer of switching formats: the cached object is a fitted ML model (not JSON-representable data), so replacing `pickle` outright is not viable here. The applicable pattern is a restricted `Unpickler` that only allows the exact model class(es) the batch job produces, gated by an HMAC signature verifying the batch job actually wrote the bytes - closing both tampering (HMAC) and arbitrary-class construction (restricted `find_class`) at once. The batch-training job (out of scope per the file's own comment) must be updated to compute and store that signature alongside each cached model; this fix cannot be complete without that companion change.

Vulnerable code:

```python
import pickle

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis()


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; that job is not part of this change.
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
    model = pickle.loads(cached)

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

Fixed code:

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

# Shared secret with the batch-training job that signs each cached model.
# Provision via a secrets manager / environment, never hardcode.
MODEL_CACHE_HMAC_KEY = os.environb[b"MODEL_CACHE_HMAC_KEY"]

# Exact (module, qualname) pairs the batch-training job is known to emit.
# Extend only when a new model type is intentionally added to the pipeline.
_ALLOWED_MODEL_CLASSES = {
    ("sklearn.linear_model._logistic", "LogisticRegression"),
}


class _RestrictedModelUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in _ALLOWED_MODEL_CLASSES:
            raise pickle.UnpicklingError(
                f"Refusing to construct disallowed class {module}.{name}"
            )
        return super().find_class(module, name)


def _load_trusted_model(model_name, payload):
    # The batch-training job must write this signature alongside the
    # pickled model: hmac.new(MODEL_CACHE_HMAC_KEY, payload, hashlib.sha256).digest()
    signature = cache.get(f"model:{model_name}:sig")
    expected = hmac.new(MODEL_CACHE_HMAC_KEY, payload, hashlib.sha256).digest()
    if signature is None or not hmac.compare_digest(signature, expected):
        raise ValueError(f"model:{model_name} failed integrity check")
    return _RestrictedModelUnpickler(io.BytesIO(payload)).load()


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; that job is not part of this change.
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    try:
        model = _load_trusted_model(model_name, cached)
    except (ValueError, pickle.UnpicklingError):
        return jsonify(error="model failed integrity check"), 500

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

## Explanation

The fix keeps `pickle` (unavoidable for a fitted model object) but removes the two things that make it exploitable: an unauthenticated payload and an unrestricted class set. `hmac.compare_digest` against a signature the batch job computes at write time proves the bytes came from that job and were not altered in the cache, closing the tampering/poisoning path; `_RestrictedModelUnpickler.find_class` then limits object construction to the specific model class(es) the pipeline actually produces, so even a validly-signed-but-unexpected payload (e.g. from a bug or a compromised signing key) cannot instantiate an arbitrary class with a `__reduce__` gadget. Either control alone is incomplete - the restricted unpickler stops arbitrary classes but not a swapped instance of an allowed class with attacker-chosen constructor arguments, and the HMAC alone stops tampering but not a legitimately-signed payload of the wrong type - so the knowledge base calls for both together, and only as a last resort because the object being cached cannot be represented as a safe interchange format like JSON.

## Behaviour changes

- Added `_load_trusted_model()` requiring a companion `model:{model_name}:sig` key; this key does not exist for any model already cached before this fix ships, and the batch-training job (out of scope for this file) must be updated to write it or every prediction request will start returning `500` until the next nightly run repopulates both keys.
- New failure path: a missing/invalid signature or a disallowed class now returns `500 {"error": "model failed integrity check"}` instead of either succeeding or raising an unhandled `UnpicklingError`. This is a deliberate, security-motivated behavior change, not a side effect - it converts what could be silent code execution into an explicit rejection.
- `_ALLOWED_MODEL_CLASSES` is populated with a single placeholder entry (`sklearn.linear_model._logistic.LogisticRegression`) because the actual model class(es) produced by the batch-training job are not visible in this file; it must be filled in with every class the pipeline legitimately emits, or legitimate predictions will be rejected.
- No change to the `/predictions/<model_name>` route signature, the 404 "model not ready" branch, or the successful-response shape (`jsonify(prediction=prediction)`); the sink's return value and success-path contract are preserved.
