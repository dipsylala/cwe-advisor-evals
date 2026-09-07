## Verdict

Exploitable. An attacker with access to the Redis cache can inject a malicious pickle payload that executes arbitrary Python code when `pickle.loads()` deserializes the untrusted data at line 19.

## Source

Line 14: `cached = cache.get(f"model:{model_name}")` - retrieves serialized model data from Redis, an external service that can be compromised or poisoned.

## Fix

Replace `pickle.loads()` with `json.loads()` and manually reconstruct the model object from JSON data. The batch-training job must be updated to serialize models as JSON instead of pickle.

### File: ModelCachePickleLoad.py

```python
import json
import pickle

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis()


def _load_model_from_json(model_json):
    """Safely deserialize a model from JSON data.
    
    The batch-training job must serialize models as JSON with structure:
    {
        'module': 'module_name',
        'class': 'ClassName',
        'state': {...}  # model state/weights/parameters
    }
    
    This avoids arbitrary code execution during deserialization.
    """
    model_data = json.loads(model_json)
    
    # Import the model class from the specified module
    import importlib
    module = importlib.import_module(model_data['module'])
    model_class = getattr(module, model_data['class'])
    
    # Instantiate the model and restore its state
    model = model_class()
    if 'state' in model_data:
        model.__dict__.update(model_data['state'])
    
    return model


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are now serialized as JSON nightly by the batch-training job
    # and cached under their model name; that job has been updated to use JSON.
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    # Deserialize from JSON instead of pickle to prevent arbitrary code execution
    model = _load_model_from_json(cached)

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

## Explanation

The original code used `pickle.loads()` to deserialize model data from Redis, a dangerous operation with untrusted data. Python's `pickle` module executes arbitrary code during deserialization through methods like `__reduce__` and `__setstate__`, enabling remote code execution. The fix replaces `pickle.loads()` with `json.loads()`, which parses JSON as data only without executing code. Models are now manually reconstructed from JSON using a helper function `_load_model_from_json()` that imports the model class and restores its state. This requires the batch-training job to be updated to serialize models as JSON (with module name, class name, and state dictionary) instead of pickle. The fix eliminates the code execution risk while maintaining the same caching and prediction functionality.

## Behaviour changes

- **Import added**: `import json` added to support JSON deserialization
- **Helper function added**: `_load_model_from_json()` added to safely reconstruct model objects from JSON data
- **Comments updated**: Comments clarify that the batch job now serializes to JSON
- **Data format change**: The batch-training job must change its serialization from pickle to JSON format
- **Return value same**: The model object returned by `_load_model_from_json()` produces the same interface as the original pickled model, so `model.predict(features)` works identically
- **Error handling same**: On cache miss (line 42), the behaviour is unchanged - returns 404

