## Verdict

CWE-502 confirmed. Line 19 uses `pickle.loads()` to deserialize model objects loaded from Redis cache. Pickle deserialization executes arbitrary Python bytecode during unpickling, making it unsafe for any data that could be tampered with or come from an attacker-controlled source.

## Source

Line 19: `model = pickle.loads(cached)`

The code retrieves a cached value from Redis and immediately deserializes it using pickle without any validation or safeguards. The cached data originates from a nightly batch training job, but relying on internal infrastructure as a trust boundary is insufficient — cache poisoning through Redis compromise, network interception, or log injection could introduce malicious pickled objects.

## Fix

Replace pickle serialization with JSON, which does not execute code during deserialization:

1. **In the cache writer** (batch training job, not shown): Serialize the model using `json.dumps()` instead of `pickle.dumps()`. If the model object cannot be directly JSON-serialized, convert it to a dict of safe types (numpy arrays as lists, coefficients as floats) before serializing.

2. **In the cache reader** (line 19): Replace `pickle.loads(cached)` with `json.loads(cached)`, then reconstruct the model from the deserialized dict. For example, if the model is a scikit-learn `LinearRegression`, parse the coefficients and intercept from JSON and create a new model instance.

3. **If pickle is unavoidable** (for complex nested objects scikit-learn or similar): Use `pickle.loads(cached, fix_imports=True)` paired with a custom `Unpickler` subclass that overrides `find_class()` to whitelist only safe model classes from trusted modules (e.g., `sklearn.linear_model.LinearRegression`). This prevents arbitrary class instantiation but does not prevent code execution for whitelisted classes — JSON is strongly preferred.

## Explanation

Pickle's protocol is not a safe serialization format; it is Python-specific and designed for compatibility over security. During unpickling, Python calls `__setstate__`, `__reduce__`, and other magic methods that can execute arbitrary code. An attacker who controls the cached data — whether through Redis compromise, network MITM, or application logic bugs — can execute arbitrary Python in the application's context.

JSON is a human-readable text format that deserializes to only primitives (strings, numbers, bools, null) and containers (objects, arrays); it cannot instantiate classes or call methods during parsing. Switching to JSON requires converting the model to a serializable dict (coefficients, metadata, hyperparameters), then reconstructing the model in code—a small additional step that eliminates the deserialization attack surface.

If the model object is too complex for JSON (e.g., complex nested scikit-learn pipelines), prefer libraries like `joblib.dump()/load()` designed for ML models, which still offer safeguards, or use pickle with a whitelist of allowed classes.
