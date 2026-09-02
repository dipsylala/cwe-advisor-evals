## Verdict

Real issue. Line 19 deserializes untrusted Redis cache data using `pickle.loads()`, which executes arbitrary Python code during object reconstruction. An attacker with Redis access or cache-poisoning capability can inject malicious pickle payloads to achieve remote code execution.

## Source

The `model_name` parameter from the URL path `/predictions/<model_name>` (line 10) controls which cache entry is retrieved (line 14). The retrieved data from Redis is passed directly to `pickle.loads()` (line 19) without integrity or type validation. Pickle's code execution during deserialization creates an exploitable sink.

## Fix

Replace pickle serialization with JSON. Change the cache storage format from pickle to JSON and reconstruct the model object from a dictionary:

```python
import json

@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # Deserialize JSON instead of pickle
    model_data = json.loads(cached)
    
    # Reconstruct model object from dictionary
    # (adapt based on actual model class structure)
    model = reconstruct_model(model_data)
    
    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

The batch-training job that stores models nightly (line 12 comment) must also be updated to serialize models as JSON instead of pickle. A helper function `reconstruct_model()` deserializes the dictionary into the model object with validated types.

## Explanation

Python's `pickle` module executes arbitrary code via `__reduce__` and `__setstate__` methods during deserialization, making it unsafe for untrusted data. JSON is a text-based format that cannot instantiate arbitrary classes or execute code—it deserializes only into dictionaries, lists, strings, numbers, and booleans. Replacing `pickle.loads(cached)` with `json.loads(cached)` eliminates code execution. Manual reconstruction of the model from the JSON dictionary enforces type safety and allows validation of the structure before use.

## Behaviour changes

- **Serialization format**: Cache entries change from binary pickle format to JSON text.
- **Deserialization**: `pickle.loads()` is replaced with `json.loads()`, returning a dictionary instead of a model object.
- **Object reconstruction**: Model object must be manually reconstructed from the dictionary via a validation function, adding a type-safety gate before the model is used.
- **Storage schema**: The batch-training job must write models in JSON format (e.g., storing model weights, parameters, and metadata as a JSON structure) instead of pickling the entire object.
- **Runtime overhead**: JSON parsing is slightly slower than pickle but negligible for typical model cache sizes; the security gain justifies the trade-off.
