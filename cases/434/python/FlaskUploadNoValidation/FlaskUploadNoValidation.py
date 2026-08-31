from flask import Flask, request
import os

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg"}


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    filename = file.filename

    if file.content_type in ALLOWED_CONTENT_TYPES:
        destination = os.path.join(UPLOAD_DIR, filename)
        # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
        file.save(destination)
        return {"status": "ok", "path": destination}, 200

    return {"status": "rejected"}, 400


if __name__ == "__main__":
    app.run()
