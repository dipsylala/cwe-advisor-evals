using ChatApp.Hubs;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(/* configured elsewhere */);
builder.Services.AddAuthorization();
builder.Services.AddSignalR();
builder.Services.AddSingleton<IChatMessageStore, ChatMessageStore>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapHub<ChatHub>("/hubs/chat");

app.Run();
