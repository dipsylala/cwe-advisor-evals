using System;
using System.Web;
using System.Web.UI;

namespace EvalCases
{
    // ASP.NET Web Forms page that echoes the last search term back into an
    // inline script block so a client-side analytics helper can log it.
    public partial class SearchResultsPage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Untrusted input: raw query string value from the request.
            string searchTerm = Request.QueryString["q"];

            string script =
                "<script>" +
                "var lastSearch = '" + searchTerm + "';" +
                "trackSearch(lastSearch);" +
                "</script>";

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            Response.Write(script);
        }
    }
}
