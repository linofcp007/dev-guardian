using Microsoft.AspNetCore.Builder;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// C10 control
app.MapGet("/minimal/health", () => "ok");

// C11 with a chained metadata call
app.MapPost("/minimal/orders", () => Results.Created()).RequireAuthorization();

// C12 route group
var admin = app.MapGroup("/admin");
admin.MapGet("/stats", () => "s");

// C13 MapMethods
app.MapMethods("/minimal/either", new[] { "GET", "POST" }, () => "e");

// C14 env
var e1 = Environment.GetEnvironmentVariable("ONE_ARG");
var e2 = Environment.GetEnvironmentVariable("TWO_ARG", EnvironmentVariableTarget.Process);
var e3 = builder.Configuration["Config:Key"];

app.Run();
