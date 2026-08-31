import socket


def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"user:bio:{username}"
    # SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    conn.sendall(f"SET {key} {bio}\r\n".encode())
    response = conn.recv(1024)
    conn.close()
    return response
