using Microsoft.AspNetCore.Mvc;

namespace OrderPortal.Controllers
{
    public class TrackingController : Controller
    {
        [HttpGet("/tracking/confirm")]
        public IActionResult Confirm()
        {
            string orderId = Request.Query["orderId"];
            string customerNote = Request.Query["note"];

            string html = "<html><body>" +
                "<h2>Tracking Confirmation</h2>" +
                "<p>Order: " + orderId + "</p>" +
                "<p>Note from customer: " + customerNote + "</p>" +
                "</body></html>";

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            return Content(html, "text/html");
        }
    }
}
