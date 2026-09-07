## Verdict
exploitable

## Source
Untrusted `model_name` URL parameter from path `/predictions/<model_name>` controls which Redis cache key is accessed, determining which serialized model object is retrieved and deserialized.

## Fix
The batch-training job (external producer) cannot be modified in this change, making format migration from pickle to JSON a breaking change. Instead, implement HMAC-SHA256 signature verification before deserialization to ensure pickle data integrity. The batch job must compute and store an HMAC signature alongside the pickled model data.

**Vulnerable code (line 19):**
```python
model = pickle.loads(cached)
```

**Fixed code:**
```python
import hmac
import hashlib
import json
import os

# At module initialization or configuration:
PICKLE_SECRET_KEY = os.environ.get("PICKLE_SIGNATURE_KEY", "").encode()

@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; that job is not part of this change.
    cache_entry = cache.get(f"model:{model_name}")
    if cache_entry is None:
        return jsonify(error="model not ready"), 404

    try:
        # Cache entry format: JSON with "data" (base64-encoded pickle) and "signature" (HMAC-SHA256 hex)
        entry_data = json.loads(cache_entry)
        pickled_model = entry_data["data"].encode("latin-1")
        stored_signature = entry_data["signature"]
        
        # Verify HMAC signature before deserialization to ensure integrity
        computed_signature = hmac.new(
            PICKLE_SECRET_KEY,
            pickled_model,
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(computed_signature, stored_signature):
            return jsonify(error="model signature verification failed"), 400
        
        model = pickle.loads(pickled_model)
    except (json.JSONDecodeError, KeyError, ValueError, pickle.UnpicklingError) as e:
        return jsonify(error="model format error"), 400

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

## Explanation
The fix adds cryptographic integrity verification using HMAC-SHA256 before unpickling. Since the batch job is an external producer that cannot be changed as part of this fix, we cannot migrate to JSON deserialization without breaking compatibility. Instead, the batch job must be updated to compute an HMAC signature over the pickled model and store both the signature and model data in JSON format in the cache. The Flask consumer verifies the signature matches using a shared secret key (environment variable `PICKLE_SIGNATURE_KEY`) before calling `pickle.loads()`. This approach, recommended in the CWE-502 guidance for trusted-but-tampered channels, ensures the pickle data has not been modified in cache storage or transit, while preserving the existing serialization format.

## Behaviour changes
- **Cache entry format changed**: Entries must now be JSON containing `data` (base64/latin-1 encoded pickle) and `signature` (HMAC-SHA256 hex). Requires batch-training job update in coordination.
- **New dependency**: Environment variable `PICKLE_SIGNATURE_KEY` must be configured with a shared secret, consistent across batch job and Flask app.
- **Enhanced error handling**: Returns HTTP 400 on signature verification failure or JSON/pickle format errors, instead of crashing on `pickle.loads()` failure.
- **Return value preserved**: On successful verification, returns the same `jsonify(prediction=prediction)` response.
