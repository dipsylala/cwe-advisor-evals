## Verdict

Confirmed. `pickle.loads(cached)` on line 19 deserializes bytes read straight from Redis under a key that embeds the request-supplied `model_name` (`f"model:{model_name}"`, line 14). The comment that a nightly batch job is the normal writer does not make the read trustworthy: `pickle.loads` has no way to tell a legitimately-written payload from one an attacker placed under the same key namespace. Anyone able to write into that Redis keyspace — a Redis instance without auth, one reachable via SSRF, a shared/multi-tenant cache, a compromised batch-job credential, or simply another service that also has `SET` access to `model:*` — gets arbitrary code execution the moment a client requests that model name, because `pickle` executes constructor calls and `__reduce__` payloads during deserialization.

## Source

`cache.get(f"model:{model_name}")` at line 14 (Redis GET, key partly attacker-influenced) — the returned bytes flow unchanged into `pickle.loads(cached)` at line 19, the deserialization sink.

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

# Shared secret used to sign/verify cached model blobs. Must be set in the
# environment for both this service and the nightly batch-training job that
# writes to the cache; never hard-code it.
MODEL_CACHE_SIGNING_KEY = os.environ["MODEL_CACHE_SIGNING_KEY"].encode()

# Only these dotted names may be constructed while unpickling a cached
# model. Extend this allowlist deliberately when a new model type is
# introduced; do not widen it to whole modules.
_ALLOWED_UNPICKLE_CLASSES = {
    ("sklearn.linear_model._logistic", "LogisticRegression"),
    ("sklearn.ensemble._forest", "RandomForestClassifier"),
    ("xgboost.sklearn", "XGBClassifier"),
    ("numpy", "ndarray"),
    ("numpy.core.multiarray", "_reconstruct"),
}


class _RestrictedModelUnpickler(pickle.Unpickler):
    """Refuses to build any class outside the model-object allowlist,
    so a forged payload can't reach os.system/subprocess/etc. even if
    it also carries a valid HMAC (e.g. via a leaked signing key)."""

    def find_class(self, module, name):
        if (module, name) not in _ALLOWED_UNPICKLE_CLASSES:
            raise pickle.UnpicklingError(
                f"Refusing to unpickle disallowed class {module}.{name}"
            )
        return super().find_class(module, name)


def _sign(payload: bytes) -> bytes:
    return hmac.new(MODEL_CACHE_SIGNING_KEY, payload, hashlib.sha256).digest()


def load_trusted_model(cached: bytes):
    """Verify integrity/authenticity before touching pickle, then
    deserialize with a class allowlist as defense in depth."""
    digest_len = hashlib.sha256().digest_size
    if cached is None or len(cached) <= digest_len:
        raise ValueError("cached model entry is missing or truncated")

    signature, payload = cached[:digest_len], cached[digest_len:]
    expected = _sign(payload)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("cached model entry failed signature verification")

    return _RestrictedModelUnpickler(io.BytesIO(payload)).load()


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name. The batch job must now write
    # sign(payload) + payload (see _sign above) instead of a bare pickle, so
    # this handler can verify authenticity before deserializing.
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    try:
        model = load_trusted_model(cached)
    except (ValueError, pickle.UnpicklingError):
        return jsonify(error="model cache entry invalid"), 502

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

The batch-training job (out of scope for this diff, but required for the fix to work end to end) must switch from `cache.set(key, pickle.dumps(model))` to writing `_sign(payload) + payload` using the same `MODEL_CACHE_SIGNING_KEY`, where `payload = pickle.dumps(model)`.

## Explanation

`pickle.loads` is not a parser, it is a bytecode interpreter for the pickle VM: a crafted stream can invoke arbitrary callables (classically `os.system`, `subprocess.Popen`, or any importable callable) via `__reduce__`/`REDUCE` opcodes during `load()`, before any application code sees a "model" object. Because the cache key is built from the request path (`model_name`) and Redis has no concept of "this key can only ever be written by the batch job," the deserialization call at line 19 is reachable with attacker-chosen bytes any time the attacker can influence what's stored under `model:<name>` — directly (unauthenticated/shared Redis, compromised batch-job credentials) or indirectly (an unrelated write primitive elsewhere in the system that happens to touch the same keyspace).

The fix keeps `pickle` (needed here since trained model objects, e.g. scikit-learn estimators, don't serialize to JSON) but closes the gap in two layers:

1. **Authenticity/integrity, checked first.** An HMAC-SHA256 signature is computed over the payload with a secret only the batch job and this service hold, and verified with `hmac.compare_digest` (constant-time, avoiding a timing side channel) before a single byte reaches `pickle.Unpickler`. This is the primary defense: an attacker without the signing key cannot produce a payload that passes verification, no matter what bytes they write to Redis.
2. **Class allowlisting, as defense in depth.** `_RestrictedModelUnpickler.find_class` only permits constructing the specific model/array classes this service expects. If the signing key were ever leaked or reused elsewhere, this still blocks a payload from instantiating something like `os.system` or `subprocess.Popen`, because those names are never in `_ALLOWED_UNPICKLE_CLASSES`.

Both checks happen before deserialization completes, and a failure returns a 5xx rather than letting an exception from a malformed pickle propagate. Signature verification is the layer that actually stops the attack (the class allowlist alone can still be bypassed by pickle gadget chains built purely from allowed classes), so it must run first and must not be skipped even though it requires a coordinated change to the writer side.
