"""Personalized greeting page for the marketing site.

Builds a short welcome banner from a query-string name so campaign links
like /greet?name=Alex render "Hello Alex!" without a static template file
per campaign.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")

    # SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    return render_template_string(f"<h1>Hello {name}!</h1><p>Welcome back.</p>")


if __name__ == "__main__":
    app.run()
