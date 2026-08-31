using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly Socket _redisSocket;

    public PresenceController(Socket redisSocket)
    {
        _redisSocket = redisSocket;
    }

    // Updates a user's presence status ("away", "busy", custom message) by
    // writing directly to the Redis wire protocol on the shared socket.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        string command = "SET " + redisKey + " " + statusMessage + "\r\n";
        byte[] payload = Encoding.ASCII.GetBytes(command);

        // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
        _redisSocket.Send(payload);

        return Ok();
    }
}
