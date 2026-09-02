"""Plugin loading endpoint for the reporting service.

Installed report plugins (e.g. ``csv_export``, ``pdf_export``) are ordinary
importable Python modules, each exposing a module-level ``run(context)`` entry
point that the loader invokes once the module has been imported.
"""

import importlib

from flask import Flask, jsonify, request

app = Flask(__name__)


def _build_plugin_context(payload):
    return {"requested_by": payload.get("user"), "options": payload.get("options", {})}


@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    plugin_module = importlib.import_module(plugin_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
