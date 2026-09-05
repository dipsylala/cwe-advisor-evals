## Verdict

Exploitable. The `pickle.loads()` call at line 19 deserializes data from Redis without validation, allowing an attacker with cache access to craft a malicious pickle payload that executes arbitrary code during object reconstruction.

## Source

`cache.get(f"model:{model_name}")` retrieves pickled model data from Redis at line 14. An attacker with write access to the Redis cache can substitute a malicious pickle payload for the legitimate model data.

## Fix

**Vulnerable code (line 18–19):**
```python
    # SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
    model = pickle.loads(cached)
```

**Fixed code:**
```python
    import hmac
    import hashlib
    
    # Verify HMAC signature before deserializing
    cache_value = cached.split(b'|sig:')
    if len(cache_value) != 2:
        return jsonify(error="model cache corrupted"), 500
    
    pickled_data, signature = cache_value
    expected_sig = hmac.new(b'model-signing-key', pickled_data, hashlib.sha256).digest()
    if not hmac.compare_digest(signature.hex().encode(), expected_sig.hex().encode()):
        return jsonify(error="model signature verification failed"), 403
    
    # Restrict Unpickler to only deserialize safe classes
    import io
    class SafeUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            # Whitelist only the model class(es) your application needs
            if module == '__main__' and name == 'Model':
                return super().find_class(module, name)
            if module == 'sklearn.ensemble' and name in ('RandomForestClassifier', 'RandomForestRegressor'):
                return super().find_class(module, name)
            raise pickle.UnpicklingError(f"Denied: {module}.{name}")
    
    try:
        model = SafeUnpickler(io.BytesIO(pickled_data)).load()
    except pickle.UnpicklingError as e:
        return jsonify(error=f"model deserialization rejected: {e}"), 400
```

The batch-training job must be updated to sign pickled data before caching it:
```python
import hmac
import hashlib
pickled_model = pickle.dumps(trained_model)
signature = hmac.new(b'model-signing-key', pickled_model, hashlib.sha256).digest()
cache.set(f"model:{model_name}", pickled_model + b'|sig:' + signature.hex().encode())
```

## Explanation

Since the batch-training job that produces the pickled models is external to this change and cannot be assumed to switch formats, the fix adds two layers of defence: HMAC signature verification ensures the cached pickle data has not been tampered with, and a restricted `Unpickler` subclass with an explicit class whitelist prevents instantiation of arbitrary classes during deserialization. The signature verification must be coordinated with the producer so both sides use the same signing key and format. The whitelist in `find_class()` must be tailored to your actual model classes—the example shows common scikit-learn estimators; adjust it to match what `trained_model` actually contains. If the producer cannot sign the data or if model types vary too widely to safely whitelist, escalate to replacing pickle with JSON across both producer and consumer (a format-breaking change that requires coordinating with the batch-training job).

## Behaviour changes

- **Added imports**: `hmac`, `hashlib`, `io` required for signature verification and safe deserialization.
- **Added cache format**: pickled data is now stored as `{pickled_bytes}|sig:{hex_signature}` in Redis, requiring the producer to update its storage format.
- **Added error responses**: returns 500 on corrupted cache format, 403 on signature mismatch, 400 on disallowed class instantiation. Original code returned 404 only for missing models.
- **Failure mode change**: deserialization now can raise `pickle.UnpicklingError` for disallowed classes rather than silently constructing them; these are caught and returned as 400 errors instead of propagating as 500 exceptions.
- **Whitelist must be maintained**: the `find_class()` allowlist must be updated if the batch-training job adds new model types.
