using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AesEcbModeCipherController : ControllerBase
{
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("0123456789abcdef");

    [HttpGet("encrypt")]
    public IActionResult Encrypt([FromQuery] string secretNote)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(secretNote);

        using var aes = Aes.Create();
        aes.Key = Key;
        // SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        byte[] cipherBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

        return Ok(Convert.ToBase64String(cipherBytes));
    }
}
