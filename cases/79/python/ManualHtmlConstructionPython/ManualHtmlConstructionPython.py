from flask import Flask, request

app = Flask(__name__)


def lookup_ticket_status(ticket_id):
    return "Open"


@app.route("/ticket/status")
def ticket_status():
    ticket_id = request.args.get("ticket", "")
    priority = request.args.get("priority", "normal")

    if not ticket_id:
        return "<p>Please provide a ticket number.</p>", 400

    status = lookup_ticket_status(ticket_id)

    page = "<html><body>"
    page += "<h2>Support Ticket Lookup</h2>"
    page += "<p>Ticket: " + ticket_id + "</p>"
    page += "<p>Priority: " + priority + "</p>"
    page += "<p>Status: " + status + "</p>"
    page += "</body></html>"

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return page
