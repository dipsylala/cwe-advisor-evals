## Verdict

Exploitable. The exception message from line 22 exposes file system paths and internal error details to the client.

## Source

User-controlled `receipt_id` from `request.args.get("id")` passed to `os.path.join(RECEIPTS_DIR, f"{receipt_id}.json")`, triggering exceptions when the file does not exist or cannot be read.

## Fix

**Vulnerable code (line 22):**
```python
    except Exception as e:
        # SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
        return jsonify({"error": str(e)}), 500
```

**Fixed code:**
```python
    except Exception as e:
        # Log the full exception server-side for debugging
        app.logger.error("Failed to retrieve receipt", exc_info=True)
        # Return generic error message to client
        return jsonify({"error": "An error occurred while retrieving the receipt"}), 500
```

## Explanation

The original code returns `str(e)` directly in the JSON response, which exposes sensitive information: file paths like `/var/data/receipts/malicious.json`, stack traces revealing the application structure, and internal error details. The fix separates user-facing and internal error handling by logging the full exception server-side with `exc_info=True` (which captures the complete traceback) and returning only a generic, server-controlled message to the client. This closes the information leak while preserving the ability to debug the issue through server logs.

## Behaviour changes

The client response message changes from the raw exception string to a generic error message. This prevents information leakage but users will no longer see specific error details in responses. All debugging information remains available server-side in application logs, where it is protected from client access.
