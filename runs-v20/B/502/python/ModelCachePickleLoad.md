## Verdict

- CWE-502 (Deserialization of Untrusted Data)
- Location: `ModelCachePickleLoad.py`, line 19, function `get_prediction`
- Verdict: exploitable
- Confidence: medium - the untrusted-channel condition is clearly present in the given file, but the only file in the call chain is this handler; the batch-training job that produces the cached value, and any Redis access controls around it, are not available to inspect, so the exact write-access path an attacker would use is inferred rather than observed.
- Library recommendation: none. The fix uses only the Python standard library (`hmac`, `hashlib`) already implicitly available; no new dependency or version bump is needed.

## Source

`cache.get(f"model:{model_name}")` returns whatever bytes currently sit under the `model:<name>` key in the shared Redis instance. The comment on lines 12-13 states a batch-training job is the intended writer, but nothing in this code path authenticates that the bytes actually came from that job - any caller with write access to this Redis keyspace (a compromised or network-exposed Redis instance, a separate vulnerability elsewhere in the system that allows an arbitrary `SET`, or another tenant/service sharing the same instance) can place its own bytes under any `model:<name>` key. `model_name` itself comes straight from the URL path and is used unvalidated to build that key, so the attacker also chooses which key to target. The value read back is treated as fully trusted serialized data with no integrity check before being handed to `pickle.loads()`.

## Fix

### File: ModelCachePickleLoad.py

```python
import hashlib
import hmac
import os
import pickle

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis()

# Shared secret the batch-training job uses to sign each pickled model before
# writing it to Redis. It must be provisioned identically on both sides (e.g.
# from the same secrets manager entry) - anyone without it cannot produce a
# signature this endpoint will accept, so a value written to the "model:*"
# keyspace by anything other than that job is rejected before unpickling.
_MODEL_CACHE_HMAC_KEY = os.environ["MODEL_CACHE_HMAC_KEY"].encode()

_SIGNATURE_LENGTH = hashlib.sha256().digest_size  # 32 bytes, raw (not hex)


def _verify_and_load_model(cache_entry):
    """Verify the HMAC-SHA256 prefix the batch-training job attaches to each
    pickled model, then unpickle only the payload that passed verification.

    Expected wire format: 32 raw signature bytes followed by the pickle
    payload, i.e. hmac.new(key, payload, "sha256").digest() + payload.
    """
    signature, payload = (
        cache_entry[:_SIGNATURE_LENGTH],
        cache_entry[_SIGNATURE_LENGTH:],
    )
    expected = hmac.new(_MODEL_CACHE_HMAC_KEY, payload, hashlib.sha256).digest()
    if not payload or not hmac.compare_digest(signature, expected):
        raise ValueError("model cache entry failed integrity verification")
    return pickle.loads(payload)


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; that job is not part of this change.
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # Cache entries are verified against an HMAC the batch-training job signs
    # them with before they are unpickled, so a value that was written or
    # altered by anything without that shared secret is rejected here instead
    # of being deserialized.
    model = _verify_and_load_model(cached)

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

## Explanation

The vulnerability is that `pickle.loads()` at line 19 deserializes a Redis value with no check that it actually came from the trusted batch-training job, so anything able to write into the `model:*` keyspace can substitute an attacker-crafted pickle payload and achieve arbitrary code execution when it is unpickled. Per the loaded CWE-502 guidance, the producer of this data (the nightly batch job) is explicitly out of scope for this change, which rules out swapping the wire format to JSON - that would require the producer to change in lockstep or every legitimate cache read would break. Instead the fix keeps pickle as the format and closes the actual gap: an HMAC-SHA256 signature, computed with a secret shared only between the batch-training job and this service, is prefixed to the payload when it is written; `_verify_and_load_model` recomputes that signature over the payload bytes and rejects (via `hmac.compare_digest`, which avoids a timing side-channel) anything that doesn't match before `pickle.loads()` ever runs. This directly addresses the exploitable condition - an unauthenticated write to the cache - without requiring knowledge of the model's class hierarchy, which this file does not expose.

## Behaviour changes

- New required environment variable `MODEL_CACHE_HMAC_KEY`: the module now raises `KeyError` at import time if it is unset. This is a deliberate, visible failure so the service cannot start in a state where cache entries would be accepted without verification; it must be provisioned (identically on the batch-training job's side) before deploy.
- Requires a companion change to the batch-training job (not in this file, out of scope for this fix): it must prepend `hmac.new(key, payload, hashlib.sha256).digest()` to each pickled model before writing it to Redis. Cache entries written before that change lack the signature and will fail verification (raising `ValueError`) rather than being silently accepted - existing cached entries will need to be regenerated by the updated job after both sides deploy. This is a deliberate fail-closed transition, not a silent regression.
- Did not add a restricted-`Unpickler`/class-allowlist layer (the KB's stated "last resort" defense-in-depth for this exact trusted-producer-but-tamperable-channel scenario). This file gives no visibility into what class(es) the cached model actually deserializes to, so hardcoding an allowlist would be a guess that risks rejecting legitimate models; the HMAC check is the guidance's primary control for this scenario and is implemented in full. Recorded as an assumption/limitation rather than added speculatively.
- Failure behaviour is otherwise unchanged: a verification failure raises an uncaught exception the same way a malformed `pickle.loads()` input would have under the original code, so Flask's default error handling (500) still applies - no new `try/except` was added that could swallow an integrity failure.
- No change to the success-path return value, to `model.predict(features)`, or to the `features` argument - those are outside the CWE-502 finding.
- Verification: `python -m py_compile` against the fixed file succeeded with no errors. All new names are Python standard library (`hmac.new`, `hmac.compare_digest`, `hashlib.sha256`, `.digest_size`, `.digest()`, `os.environ`) - no new third-party dependency introduced. No test harness or live Redis/batch-job instance was available in this environment to exercise the signed-payload round trip end to end.
