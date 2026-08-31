using System;
using System.Web;
using System.Web.UI;

namespace EvalCases.WebForms
{
    public class FeedbackStatusHandler : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string ticketRef = Request.QueryString["ticketRef"];

            Response.ContentType = "text/html";
            Response.Write("<html><body>");
            Response.Write("<h2>Support Ticket Lookup</h2>");

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");

            Response.Write("</body></html>");
        }
    }
}
