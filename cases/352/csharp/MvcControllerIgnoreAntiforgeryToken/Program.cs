using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Global CSRF protection: every state-changing MVC action is validated by
// default, so individual actions do not need [ValidateAntiForgeryToken].
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});
builder.Services.AddAntiforgery();

builder.Services.AddScoped<IAccountSettingsService, AccountSettingsService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
