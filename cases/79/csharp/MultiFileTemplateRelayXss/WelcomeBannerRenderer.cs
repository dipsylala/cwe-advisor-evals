using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace ContosoPortal.Profile
{
    public class WelcomeBannerRenderer
    {
        public async Task Write(HttpResponse response, BannerContent banner)
        {
            response.ContentType = "text/html";
            string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! Last visit logged at {banner.RequestedAt:u}.</div>";

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            await response.WriteAsync(html);
        }
    }
}
