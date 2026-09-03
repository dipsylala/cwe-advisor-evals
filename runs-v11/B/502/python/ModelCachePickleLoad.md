## Verdict

Exploitable. High confidence.

CWE-502 on line 19: `pickle.loads(cached)` deserializes untrusted data from Redis without integrity verification. The data source (Redis cache) is accessible to an attacker who can poison the cache with a malicious pickle payload. Pickle's `__reduce__` and `__setstate__` mechanisms enable arbitrary code execution during deserialization.

## Source

**Source (untrusted data origin):** Redis cache lookup at line 14: `cached = cache.get(f"model:{model_name}")`

**Sink (deserialization):** Line 19: `model = pickle.loads(cached)`

**Data flow:** An attacker who compromises or poisons the Redis cache can inject a malicious pickle-serialized object. When the `get_prediction()` endpoint is called, the poisoned data is retrieved from Redis and deserialized without validation, executing attacker-controlled code during object reconstruction.

## Fix

**Vulnerable code:**
```python
@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # SAST FINDING: CWE-502 (Deserialization of Untrusted Data) - pickle.loads() on untrusted data
    model = pickle.loads(cached)

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

**Fixed code:**
```python
import json

@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # Deserialize from safe JSON format instead of pickle
    try:
        model_data = json.loads(cached.decode('utf-8'))
    except (json.JSONDecodeError, ValueError, AttributeError):
        return jsonify(error="invalid model format"), 500

    # Reconstruct model object from JSON representation
    # (Implementation depends on model type - shown as example for sklearn-like models)
    model = reconstruct_model_from_json(model_data)
    if model is None:
        return jsonify(error="model reconstruction failed"), 500

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)

def reconstruct_model_from_json(model_data):
    """
    Safely reconstruct a model object from JSON representation.
    This function must explicitly instantiate only expected model types
    and validate all fields before object creation.
    """
    try:
        model_type = model_data.get("type")
        if model_type not in ["sklearn_classifier", "sklearn_regressor"]:
            return None
        
        # Load model coefficients/weights from JSON
        coefficients = model_data.get("coefficients")
        if not isinstance(coefficients, list):
            return None
        
        # Instantiate safe model class and populate from trusted JSON data
        model = YourModelClass()
        model.coefficients = coefficients
        return model
    except (KeyError, TypeError, ValueError):
        return None
```

## Explanation

Pickle's deserialization process executes arbitrary Python code through methods like `__reduce__` and `__setstate__`, enabling remote code execution if an attacker controls the serialized data. Redis, while useful for caching, is not a trust boundary—a compromised Redis instance or network-level attack can poison the cache with malicious payloads.

The fix replaces `pickle.loads()` with `json.loads()`, which deserializes only data structures (dicts, lists, strings, numbers) without instantiating arbitrary classes or executing methods. This eliminates code execution during deserialization. The model object is then reconstructed explicitly from validated JSON fields using a safe, allowlisted reconstruction function that accepts only expected model types and validates all incoming fields before object creation. This enforces both format safety (JSON has no code execution) and type safety (only approved model classes are instantiated).

Note: This fix requires the upstream batch training job to serialize models as JSON instead of pickle. If the batch job cannot be modified, the alternative is to add HMAC-SHA256 signature verification to detect tampering: sign the pickled bytes with a shared secret before caching, and verify the signature before deserializing. However, HMAC only protects against tampering; it does not prevent exploitation of vulnerable pickle gadget chains if the attacker has knowledge of installed libraries. JSON serialization is the preferred primary fix per security guidance.

## Behaviour changes

**Model serialization format:** The batch job must change from pickle to JSON. Serialization format change requires updating the upstream training pipeline to export models as JSON with explicit fields (type, coefficients, etc.) rather than relying on pickle to preserve the object structure.

**Deserialization error handling:** The fixed code adds explicit error handling for JSON decode failures and model reconstruction failures. Malformed JSON or unrecognized model types now return HTTP 500 with a descriptive error, whereas the original code would raise an unhandled exception. This is a safety improvement (explicit error messages vs. potential server crash).

**Model reconstruction:** The original code relied on pickle to instantiate and populate the model object automatically. The fixed code requires explicit reconstruction logic that validates and sets only expected fields. This adds a small computational overhead during deserialization but is negligible for typical model sizes.

**Type safety:** The fixed code only instantiates model classes present in the `reconstruct_model_from_json` allowlist. The original code using pickle could instantiate any Python class reachable from the pickle payload, enabling arbitrary object creation. The fixed code eliminates this attack surface.

**Dependencies:** Requires no new Python packages beyond the standard library (json module). If models are complex (e.g., scikit-learn pipelines, TensorFlow models), you may need to implement domain-specific reconstruction logic or use alternative serialization formats like Protocol Buffers (protobuf) or ONNX for ML models, as recommended in the broader CWE-502 guidance.
