from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


def lookup_ticket_status(ticket_id):
    # Stubbed lookup for the purposes of this example.
    return "open"


@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    # The caller-supplied label is wrapped in Markup() so it can sit next to
    # the status badge without Jinja2 escaping it when the page is rendered.
    safe_label = Markup(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return f"<html><body>{banner}</body></html>"
