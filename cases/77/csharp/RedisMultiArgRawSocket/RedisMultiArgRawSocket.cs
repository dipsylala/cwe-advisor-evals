using System;
using System.Net.Sockets;
using System.Text;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly Socket _redisSocket;

        public SessionNoteWriter(Socket redisSocket)
        {
            _redisSocket = redisSocket;
        }

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string command =
                "HSET session:" + sessionId +
                " note " + agentNote +
                " updated " + updatedAt +
                "\r\n";

            byte[] payload = Encoding.ASCII.GetBytes(command);
            // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
            _redisSocket.Send(payload);
        }
    }
}
