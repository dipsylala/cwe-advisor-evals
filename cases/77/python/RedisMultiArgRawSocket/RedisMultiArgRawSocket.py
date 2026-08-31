import socket


def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"session:{session_id}"
    # SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())
    response = conn.recv(1024)
    conn.close()
    return response
