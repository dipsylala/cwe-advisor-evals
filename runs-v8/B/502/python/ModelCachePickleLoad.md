## Verdict

Exploitable. The `pickle.loads()` call deserializes data from Redis without integrity verification. Pickle's deserialization mechanism executes arbitrary code via `__reduce__` or `__setstate__` methods during object reconstruction. An attacker with write access to Redis (through misconfiguration, compromise of the batch-training job, or network exposure) can craft a malicious pickle payload that executes arbitrary system commands.

## Source

`cache.get(f"model:{model_name}")` retrieves serialized model data from Redis (line 14). The model name is derived from the URL path parameter but the actual risk is from the cached data itself: Redis is populated by a batch-training job and could be compromised or poisoned. Pickle data cannot be validated without full deserialization, which is when code execution occurs.

## Fix

**Vulnerable Code:**
```python
import pickle

# Line 19
model = pickle.loads(cached)
```

**Fixed Code:**
```python
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    """Restrict unpickling to an allowlist of safe model classes."""
    
    # Whitelist known-safe model classes that batch-training job produces
    SAFE_MODEL_CLASSES = {
        ('sklearn.pipeline', 'Pipeline'),
        ('sklearn.tree', 'DecisionTreeClassifier'),
        ('sklearn.tree', 'DecisionTreeRegressor'),
        ('sklearn.ensemble', 'RandomForestClassifier'),
        ('sklearn.ensemble', 'RandomForestRegressor'),
        ('sklearn.linear_model', 'LogisticRegression'),
        ('sklearn.linear_model', 'LinearRegression'),
        ('sklearn.svm', 'SVC'),
        # Add other model classes your batch-training job produces
    }
    
    def find_class(self, module, name):
        """Block instantiation of classes not in the whitelist."""
        if (module, name) not in self.SAFE_MODEL_CLASSES:
            raise pickle.UnpicklingError(
                f"Attempted to unpickle forbidden class: {module}.{name}"
            )
        return super().find_class(module, name)

# Line 19 (replacement)
try:
    model = RestrictedUnpickler(io.BytesIO(cached)).load()
except pickle.UnpicklingError as e:
    return jsonify(error="Invalid or corrupted model data"), 400
```

## Explanation

The fix replaces unrestricted `pickle.loads()` with a `RestrictedUnpickler` that whitelists only the safe model classes your batch-training job legitimately produces. This blocks the `__reduce__` gadget chain attacks that allow code execution during deserialization. Only classes explicitly listed in `SAFE_MODEL_CLASSES` can be instantiated; attempting to unpickle any other class raises `UnpicklingError`. Error handling returns HTTP 400 to inform the caller that model data is corrupted or invalid, without exposing system internals. The whitelist must be updated whenever the batch-training job is modified to produce new model types.

**Important limitation**: Type whitelisting mitigates the most common code-execution vectors but does not eliminate all risks. For full remediation, replace pickle with JSON serialization across the batch-training job and this handler (see CWE-502 guidance for JSON + manual object reconstruction). Type whitelisting is a defense-in-depth layer, not a complete fix—pair it with network segmentation, Redis authentication, and monitoring for suspicious model cache updates.

## Behaviour changes

- Added `import io` to support `BytesIO` wrapper required by `Unpickler` constructor.
- Added `RestrictedUnpickler` class definition with a whitelist. This increases code size by ~20 lines but only loads once at module initialization.
- Changed deserialization from `pickle.loads(cached)` to `RestrictedUnpickler(io.BytesIO(cached)).load()`. Functionally equivalent for whitelisted classes; raises `UnpicklingError` (not `Exception`) for forbidden classes, which is caught and handled.
- Added try-except around deserialization. Original code would crash with unhandled `pickle.UnpicklingError` on malformed data; fixed code returns HTTP 400 with a user-facing error message. This changes the error response from 500 to 400, which is semantically correct for bad input data.
- The `model.predict(features)` call and response format are unchanged; the model object returned has the same interface.
- **No change to cache key, Redis connection, or Flask route signature.**
- **The batch-training job's pickle storage format must remain unchanged.** The whitelist must be manually maintained as new model classes are added.
