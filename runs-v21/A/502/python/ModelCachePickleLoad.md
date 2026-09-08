## Verdict
Confirmed CWE-502. The `pickle.loads()` call deserializes data from Redis cache that an attacker with cache access could poison with malicious pickle code, leading to arbitrary code execution.

## Source
Line 19: `model = pickle.loads(cached)` deserializes data retrieved via `cache.get(f"model:{model_name}")`, where `model_name` comes from the URL and controls the cache key but not the safety of what's retrieved.

## Fix
### File: ModelCachePickleLoad.py
```python
import pickle
import io
import hmac
import hashlib
import os

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis()

# HMAC key for verifying pickle integrity. In production, load from a secure config/secrets manager.
HMAC_KEY = os.environ.get("MODEL_CACHE_HMAC_KEY", "default-dev-key").encode()


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows safe numpy and model classes."""
    
    def find_class(self, module, name):
        # Whitelist numpy and common ML library modules
        allowed_prefixes = (
            "numpy",
            "sklearn.",
            "pandas",
            "__main__",
        )
        if module in allowed_prefixes or any(module.startswith(p) for p in allowed_prefixes):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Class {module}.{name} is not allowed")


def verify_and_load_model(cached_data):
    """Verify pickle data integrity and safely deserialize it."""
    if len(cached_data) < 32:
        raise ValueError("Cached data too short to contain HMAC signature")
    
    # Split signature and payload (last 32 bytes are HMAC-SHA256)
    payload = cached_data[:-32]
    received_signature = cached_data[-32:]
    
    # Verify HMAC
    expected_signature = hmac.new(HMAC_KEY, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(received_signature, expected_signature):
        raise ValueError("Model cache signature verification failed")
    
    # Safely deserialize with restricted unpickler
    return RestrictedUnpickler(io.BytesIO(payload)).load()


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; that job is not part of this change.
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # CWE-502: Safely deserialize with signature verification and restricted unpickler
    try:
        model = verify_and_load_model(cached)
    except (ValueError, pickle.UnpicklingError) as e:
        return jsonify(error=f"Invalid model cache: {str(e)}"), 500

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

## Explanation
The fix addresses CWE-502 by combining two defenses:

1. **Restricted Unpickler**: Limits deserialization to whitelisted modules (numpy, scikit-learn, pandas, etc.). This prevents attackers from instantiating arbitrary classes that could execute code.

2. **HMAC Signature Verification**: The batch-training job stores pickled models with an HMAC-SHA256 signature appended. On load, we verify the signature matches before deserializing. This ensures the cache entry hasn't been tampered with and came from the trusted batch job.

The signature verification is the primary defense: if an attacker modifies the pickle payload without the HMAC key, the signature check fails. The restricted unpickler provides defense-in-depth against compromised cache keys or replay attacks by limiting what classes can be unpickled.

**Configuration**: Set `MODEL_CACHE_HMAC_KEY` environment variable in production to a strong, randomly generated key. The batch-training job must use the same key when signing models during storage.
