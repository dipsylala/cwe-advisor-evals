## Verdict

Confirmed. `pickle.loads()` is called directly on a value read back from Redis, and that value is not something this request handler controls end to end: anything that can write to the `model:<model_name>` key (a compromised or shared Redis instance, a separate endpoint that writes to the cache, another tenant on the same keyspace, etc.) can plant a crafted pickle stream there. `pickle.loads` executes arbitrary code via `__reduce__`/`__setstate__` during load, so this is a code-execution sink on externally-influenced data, not just an internal cache read.

## Source

`cache.get(f"model:{model_name}")` at line 14 — the raw bytes returned by Redis for the computed key, which flow unchanged into `pickle.loads(cached)` at line 19. The value is attacker-reachable through anything with write access to that Redis key (the batch job is the intended writer, but the handler has no way to verify that a given cache entry actually came from it).

## Fix

### File: ModelCachePickleLoad.py
```python
import io
import pickle

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
cache = redis.Redis()

# The (module, qualname) pairs the nightly training job's pickled model
# artifacts are actually made of. Extend this only with classes the
# serialization step is known to emit - do not widen it to "whatever shows
# up", since that reopens the same hole this allowlist closes.
_ALLOWED_CLASSES = {
    ("sklearn.linear_model._base", "LinearRegression"),
    ("sklearn.linear_model._logistic", "LogisticRegression"),
    ("sklearn.ensemble._forest", "RandomForestClassifier"),
    ("sklearn.ensemble._forest", "RandomForestRegressor"),
    ("sklearn.tree._classes", "DecisionTreeClassifier"),
    ("sklearn.svm._classes", "SVC"),
    ("sklearn.preprocessing._data", "StandardScaler"),
    ("numpy", "ndarray"),
    ("numpy", "dtype"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("builtins", "list"),
    ("builtins", "dict"),
    ("builtins", "tuple"),
    ("builtins", "set"),
    ("builtins", "float"),
    ("builtins", "int"),
    ("builtins", "str"),
}


class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickles only the classes the training job's artifacts use.

    Plain pickle.loads() lets any object named in the stream run its own
    constructor/__reduce__ during load, which is what makes an untrusted
    pickle equivalent to arbitrary code execution. Overriding find_class()
    with a fixed allowlist keeps the on-disk pickle format the batch job
    already writes (so that job needs no change), while refusing to
    instantiate anything outside the expected model classes.
    """

    def find_class(self, module, name):
        if (module, name) not in _ALLOWED_CLASSES:
            raise pickle.UnpicklingError(
                f"Refusing to unpickle disallowed class {module}.{name}"
            )
        return super().find_class(module, name)


def _safe_load_model(data: bytes):
    return _RestrictedUnpickler(io.BytesIO(data)).load()


@app.get("/predictions/<model_name>")
def get_prediction(model_name):
    # Trained models are pickled nightly by the batch-training job and cached
    # under their model name; that job is not part of this change.
    cached = cache.get(f"model:{model_name}")
    if cached is None:
        return jsonify(error="model not ready"), 404

    model = _safe_load_model(cached)

    features = request.args.get("features", "")
    prediction = model.predict(features)
    return jsonify(prediction=prediction)
```

## Explanation

The batch-training job that writes these pickles is explicitly out of scope, so the fix cannot swap the cache to a different serialization format (JSON, a model-specific format, etc.) without breaking that producer, which still writes native pickle. Instead the handler keeps reading the same pickle bytes but no longer trusts the stream to name any class it likes: `_RestrictedUnpickler.find_class` is consulted for every object the pickle protocol tries to construct, and anything not in `_ALLOWED_CLASSES` raises instead of running. This removes the arbitrary-constructor/`__reduce__` execution primitive that makes `pickle.loads` on external data dangerous, while still deserializing the legitimate model objects the nightly job produces. `_ALLOWED_CLASSES` is scoped to the estimator, container, and numpy classes a typical scikit-learn model artifact is made of; it should be adjusted to match whatever the real training job actually emits, but the mechanism (allowlist the classes, not the bytes) is what closes the finding regardless of which ML library is in use.
