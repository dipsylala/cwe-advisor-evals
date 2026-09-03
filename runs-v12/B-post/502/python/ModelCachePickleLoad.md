## Verdict

Exploitable

## Source

`cache.get(f"model:{model_name}")` at line 14 retrieves serialized data from Redis cache. This data is attacker-controlled if Redis is accessible or if an attacker can inject data before caching.

## Fix

**Vulnerable code:**

```python
@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
    model = pickle.loads(cached)
    
    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

**Fixed code:**

```python
import hmac
import hashlib
import pickle
import io

@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; that job is not part of this change.
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # CWE-502 remediation: Verify HMAC signature and use restricted unpickler
    if len(cached) < 32:
        return jsonify(error="invalid model format"), 400
    
    signature = cached[:32]
    pickled_data = cached[32:]
    
    # Verify integrity using HMAC-SHA256 before any deserialization
    expected_signature = hmac.new(
        app.config['PICKLE_HMAC_KEY'].encode() if isinstance(app.config['PICKLE_HMAC_KEY'], str)
        else app.config['PICKLE_HMAC_KEY'],
        pickled_data,
        hashlib.sha256
    ).digest()
    
    if not hmac.compare_digest(signature, expected_signature):
        return jsonify(error="model verification failed"), 401
    
    # Safely deserialize using restricted unpickler that blocks unsafe classes
    try:
        model = RestrictedUnpickler(io.BytesIO(pickled_data)).load()
    except (pickle.UnpicklingError, EOFError, ValueError):
        return jsonify(error="failed to load model"), 400
    
    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that restricts which classes can be instantiated during deserialization."""
    
    # Allowlist of safe modules - extend as needed for your models
    ALLOWED_MODULES = {
        'sklearn',
        'sklearn.base',
        'sklearn.ensemble',
        'sklearn.linear_model',
        'sklearn.tree',
        'numpy',
        'numpy.core.multiarray',
        '__main__',
    }
    
    def find_class(self, module, name):
        """Override to prevent arbitrary class instantiation."""
        if not any(module.startswith(allowed) for allowed in self.ALLOWED_MODULES):
            raise pickle.UnpicklingError(
                f"Class {module}.{name} is not allowed to be unpickled"
            )
        return super().find_class(module, name)
```

Additionally, configure the HMAC key in Flask config:

```python
app.config['PICKLE_HMAC_KEY'] = 'your-strong-secret-key-from-secure-config'
```

**Ideal long-term fix:**

Replace pickle entirely with JSON serialization in both the producer (batch-training job) and consumer:

```python
import json

@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # Replace pickle.loads with JSON for safer deserialization
    try:
        model_data = json.loads(cached.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return jsonify(error="invalid model format"), 400
    
    # Manually reconstruct model object from JSON-safe data with validation
    model = reconstruct_model_from_json(model_data)
    
    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

## Explanation

Python's `pickle.loads()` executes arbitrary code during deserialization when it encounters class constructors and methods like `__reduce__` or `__setstate__`. An attacker controlling the cached pickle data can craft a malicious payload to execute arbitrary system commands with the application's privileges, leading to remote code execution (RCE).

The immediate fix uses two complementary defenses: (1) HMAC-SHA256 signature verification ensures the pickled data has not been tampered with by comparing a pre-computed signature, and (2) `RestrictedUnpickler.find_class()` overrides the class resolver to enforce a whitelist of allowed modules, preventing instantiation of dangerous classes. Combined, these mitigate the primary attack vectors while maintaining backward compatibility with existing pickled models.

The long-term solution is to replace pickle with JSON and manually reconstruct model objects from JSON dictionaries. This eliminates code execution during deserialization entirely, as JSON only produces data structures (dicts, lists, strings, numbers) without invoking any Python code. This requires coordinating with the batch-training job to change its serialization format but provides stronger security guarantees and eliminates future pickle-related vulnerabilities.

## Behaviour changes

- Added HMAC signature verification: requires pickled data to be prefixed with a 32-byte HMAC-SHA256 signature, changing the cached data format. The batch-training job must be updated to produce signatures.
- Added `RestrictedUnpickler` class: unpickler now blocks any module not in `ALLOWED_MODULES`. If legitimate models use classes outside this allowlist, the allowlist must be expanded or the class must be imported through an allowed module.
- Added error handling for signature verification failure (401 response) and format validation (400 response): previously unknown data formats would have caused unhandled pickle exceptions.
- Requires `app.config['PICKLE_HMAC_KEY']` configuration: application startup will fail if this is not set. This must be a strong, consistent secret shared between producer and consumer.
