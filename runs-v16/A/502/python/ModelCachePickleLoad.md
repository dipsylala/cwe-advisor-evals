## Verdict

Real issue. `pickle.loads()` at line 19 deserializes untrusted cache data without validation. Although the batch-training job is described as internal, pickle's design allows arbitrary code execution during deserialization; treat the cache as an untrusted boundary.

## Source

Line 14 retrieves `cached` from Redis using `cache.get(f"model:{model_name}")`. Redis returns raw bytes. Line 19 passes this directly to `pickle.loads(cached)`, which reconstructs arbitrary Python objects without restriction.

## Fix

Replace the unsafe pickle deserialization with a restricted approach using `pickle.Unpickler` and a custom `find_class` override that allows only the specific model class(es) the batch job can produce:

```python
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Allowlist only the safe classes your model can be
        # Example: sklearn estimators, neural network models, etc.
        if module == "sklearn.ensemble" and name == "RandomForestClassifier":
            return super().find_class(module, name)
        if module == "your_models" and name == "YourModelClass":
            return super().find_class(module, name)
        # Reject all other classes
        raise pickle.UnpicklingError(f"Deserialization of {module}.{name} is not allowed")

@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404
    
    model = RestrictedUnpickler(io.BytesIO(cached)).load()
    
    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

If the batch job and cache format can be changed, migrate to JSON serialization (for models with JSON-serializable representations) or a safer format like MessagePack or Protocol Buffers instead of pickle.

## Explanation

`pickle.loads()` is unsafe because pickle instantiates arbitrary classes and calls methods during deserialization—a feature that enables code injection if an attacker can write to the cache. Even internal batch jobs can be compromised or misconfigured.

The restricted unpickler whitelist only specific, known-safe classes that the batch job can legitimately produce. Any attempt to deserialize other types raises an exception. This maintains the pickle format (preserving compatibility with the existing batch job) while eliminating the code execution risk.

Update the allowlist to match the actual model classes your batch job produces.
