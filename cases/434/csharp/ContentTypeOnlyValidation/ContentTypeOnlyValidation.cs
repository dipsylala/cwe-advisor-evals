using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Hosting;

namespace ProfilePictures.Controllers
{
    [ApiController]
    [Route("api/profile")]
    public class ProfilePictureController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;

        public ProfilePictureController(IWebHostEnvironment env)
        {
            _env = env;
        }

        [HttpPost("avatar")]
        public async Task<IActionResult> UploadAvatar(IFormFile avatar)
        {
            if (avatar == null || avatar.Length == 0)
            {
                return BadRequest("No file uploaded.");
            }

            bool isAllowedImageType =
                avatar.ContentType == "image/png" ||
                avatar.ContentType == "image/jpeg" ||
                avatar.ContentType == "image/gif";

            if (!isAllowedImageType)
            {
                return BadRequest("Only PNG, JPEG, or GIF images are allowed.");
            }

            var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
            Directory.CreateDirectory(storageRoot);

            var extension = avatar.ContentType switch
            {
                "image/png" => ".png",
                "image/jpeg" => ".jpg",
                "image/gif" => ".gif",
                _ => ".bin"
            };

            var storedFileName = Guid.NewGuid().ToString("N") + extension;
            var destinationPath = Path.Combine(storageRoot, storedFileName);

            // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
            using (var destinationStream = System.IO.File.Create(destinationPath))
            {
                await avatar.CopyToAsync(destinationStream);
            }

            return Ok(new { storedFileName });
        }
    }
}
