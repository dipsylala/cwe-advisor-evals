using System.Net.Sockets;
using System.Text;

namespace MultiFileRedisCommandRelay
{
    // Writes commands directly to a Redis instance using the plain-text inline protocol,
    // bypassing StackExchange.Redis's RESP framing.
    public class RedisWireWriter
    {
        private readonly TcpClient _client;

        public RedisWireWriter(TcpClient client)
        {
            _client = client;
        }

        public void SendSetCommand(string key, string value)
        {
            string command = "SET " + key + " " + value + "\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(command);

            NetworkStream stream = _client.GetStream();
            // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
            stream.Write(payload, 0, payload.Length);
        }
    }
}
