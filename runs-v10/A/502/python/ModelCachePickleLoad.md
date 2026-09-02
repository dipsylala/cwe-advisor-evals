## Verdict

**Confirmed.** Line 19 deserializes untrusted data from Redis cache using `pickle.loads()` without validating its integrity or authenticity. An attacker who can poison the cache (through network access, credential compromise, or similar) can inject a malicious pickled object that executes arbitrary code.

## Source

The untrusted data flows from `cache.get(f"model:{model_name}")` on line 14, which retrieves an arbitrary value from Redis keyed by user-supplied input (`model_name` from the URL route). This value is passed directly to `pickle.loads(cached)` on line 19 without any integrity verification.

## Fix

Add cryptographic signing to the pickled models when they are stored, and verify the signature before deserializing:

```python
import pickle
import hmac
import hashlib

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis()
PICKLE_KEY = b"your-secret-key-from-env"  # Load from environment variable in production

def sign_pickle(obj, key):
    """Sign a pickled object with HMAC."""
    pickled = pickle.dumps(obj)
    signature = hmac.new(key, pickled, hashlib.sha256).digest()
    return pickled, signature

def verify_and_load_pickle(pickled, signature, key):
    """Verify HMAC signature before deserializing."""
    expected_signature = hmac.new(key, pickled, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("Invalid pickle signature; data may be tampered")
    return pickle.loads(pickled)

@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    cached_data = cache.get(f"model:{model_name}:pickle")
    cached_sig = cache.get(f"model:{model_name}:sig")
    
    if cached_data is None or cached_sig is None:
        return jsonify(error="model not ready"), 404
    
    try:
        model = verify_and_load_pickle(cached_data, cached_sig, PICKLE_KEY)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    
    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

The batch-training job should similarly sign models before caching them:
```python
pickled, signature = sign_pickle(trained_model, PICKLE_KEY)
cache.set(f"model:{model_name}:pickle", pickled)
cache.set(f"model:{model_name}:sig", signature)
```

## Explanation

`pickle.loads()` reconstructs Python objects by executing bytecode stored in the pickle stream. An attacker-controlled pickled object can exploit this to execute arbitrary Python code during deserialization. Since the model is retrieved from Redis—a network-accessible cache that could be compromised—the deserialized data is untrusted.

The fix uses HMAC-SHA256 to cryptographically sign the pickled model when stored. Before deserialization, the signature is verified using `hmac.compare_digest()` to prevent timing attacks. Only pickled models with valid signatures (meaning they were created by the trusted batch job) are deserialized. An attacker who tampers with the cached pickle will fail the signature check, preventing code execution.

Alternative approaches include:
- Switching to JSON serialization if the model structure allows it (safer than pickle)
- Using a restricted unpickler that limits which classes can be loaded (requires careful allowlist maintenance)
- Storing models in a secure, access-controlled location instead of a network cache
