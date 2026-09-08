## Verdict

CWE-502 confirmed. The code deserializes data from a Redis cache using `pickle.loads()` without validation. Although the source data is produced by an internal batch-training job, Redis-cached data is vulnerable to tampering. Python's `pickle` module executes arbitrary code during deserialization, enabling remote code execution if a malicious or tampered pickle is loaded. The finding is real and exploitable.

## Source

```python
cached = cache.get(f"model:{model_name}")
if cached is None:
    return jsonify(error="model not ready"), 404

model = pickle.loads(cached)  # Line 19: CWE-502 - deserialization without validation
```

The `model_name` parameter comes from the URL path and is used to construct a Redis key. The value retrieved from Redis is deserialized without any integrity or type validation. An attacker who gains access to Redis (or a network path to it) can inject a malicious pickle payload that executes arbitrary code when deserialized.

## Fix

### File: ModelCachePickleLoad.py

```python
import pickle
import hmac
import hashlib
import os
from io import BytesIO

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis()

# HMAC key for verifying pickle integrity - must be stored securely
# (e.g., environment variable, secrets manager, not hardcoded)
HMAC_KEY = os.environ.get('MODEL_CACHE_HMAC_KEY', 'default-key-change-in-production')

class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that restricts which classes can be instantiated during deserialization."""
    
    # Whitelist of classes allowed during unpickling.
    # Adjust this based on the specific model framework(s) used by your batch job.
    ALLOWED_CLASSES = {
        # NumPy
        ('numpy', 'ndarray'),
        ('numpy.core.multiarray', '_reconstruct'),
        ('numpy.ma.core', 'MaskedArray'),
        # scikit-learn (common ML framework)
        ('sklearn.tree._classes', 'DecisionTreeClassifier'),
        ('sklearn.ensemble._forest', 'RandomForestClassifier'),
        ('sklearn.linear_model._logistic', 'LogisticRegression'),
        ('sklearn.pipeline', 'Pipeline'),
        # Add other model classes as needed for your specific models
    }
    
    def find_class(self, module, name):
        """Override to restrict which classes can be instantiated."""
        if (module, name) not in self.ALLOWED_CLASSES:
            raise pickle.UnpicklingError(
                f"Unpickling {module}.{name} is not allowed"
            )
        return super().find_class(module, name)


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; that job is not part of this change.
    cached_data = cache.get(f"model:{model_name}")
    if cached_data is None:
        return jsonify(error="model not ready"), 404

    # Extract and verify HMAC signature
    try:
        stored_hmac_hex, pickled_data = cached_data.split(b':', 1)
        stored_hmac = bytes.fromhex(stored_hmac_hex.decode('utf-8'))
        
        computed_hmac = hmac.new(
            HMAC_KEY.encode('utf-8'),
            pickled_data,
            hashlib.sha256
        ).digest()
        
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            return jsonify(error="model cache verification failed"), 400
    except (ValueError, UnicodeDecodeError):
        return jsonify(error="invalid model cache format"), 400

    # Deserialize using restricted unpickler
    try:
        model = RestrictedUnpickler(BytesIO(pickled_data)).load()
    except (pickle.UnpicklingError, EOFError, AttributeError):
        return jsonify(error="failed to load model"), 400

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

## Explanation

The fix addresses CWE-502 through two complementary defences:

**1. Restricted Unpickler (Class Instantiation Control)**
A custom `RestrictedUnpickler` class overrides `find_class()` to implement an allowlist of classes that are permitted during unpickling. This prevents an attacker's malicious pickle from instantiating arbitrary classes or invoking dangerous `__reduce__()` or `__setstate__()` methods. Any attempt to instantiate a class outside the allowlist raises `UnpicklingError`. The allowlist must be tailored to the specific model classes your batch-training job produces (shown here for NumPy and scikit-learn as examples; adjust to match your actual model framework).

**2. HMAC Signature Verification (Data Integrity)**
Before deserialization, the code verifies an HMAC-SHA256 signature on the pickled data. The cached data must be formatted as `<hmac_hex>:<pickled_bytes>`. This ensures that even if an attacker gains access to Redis, they cannot modify the pickle without invalidating the signature. This addresses tampering during storage or transit, protecting a trusted-but-vulnerable storage channel.

Together, these controls ensure that:
- Only expected model classes can be instantiated, preventing code execution via class methods
- The pickled data has not been tampered with, preventing injection of malicious payloads
- Errors during verification or unpickling fail safely, returning an error response rather than crashing or executing untrusted code

The fix trades off against a limitation of the `pickle` format: this approach does not protect against a malicious producer. If the batch-training job itself is compromised, an attacker could generate a valid HMAC-signed malicious pickle. However, it does provide defence-in-depth against the most common attack path (tampering with data already in the cache).

## Behaviour changes

1. **HMAC format requirement**: The batch-training job must be updated to sign all pickled models with HMAC before storing them in Redis. Existing cache entries without HMAC signatures will fail verification and return a 400 error. The cache must be regenerated after the batch job is updated.

2. **Limited class support**: Only classes in the `ALLOWED_CLASSES` whitelist can be instantiated. If the batch job uses model classes not in the list, unpickling will fail with a 400 error. The whitelist must be maintained and kept in sync with the actual model types in use.

3. **Key management**: The HMAC key (`MODEL_CACHE_HMAC_KEY`) must be securely shared between the batch-training job and the Flask application, typically via a secure configuration or secrets manager. This introduces an operational dependency.

4. **Error responses**: Invalid cache format, verification failures, and unpickling errors now return HTTP 400 instead of raising an unhandled exception.

5. **Long-term consideration**: This is a last-resort mitigation for the pickle format's inherent risk. A more robust long-term solution would be for the batch-training job to serialize models as JSON (with manual object reconstruction) or Protocol Buffers, eliminating the deserialization vulnerability entirely.
