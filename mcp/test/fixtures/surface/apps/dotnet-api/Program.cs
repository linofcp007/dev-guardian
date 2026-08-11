using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var connectionString = Environment.GetEnvironmentVariable("SQL_CONNECTION");

app.MapGet("/minimal/health", () => Results.Ok(new { ok = true }));
app.MapPost("/minimal/orders", (Order order) => Results.Created($"/minimal/orders/{order.Id}", order));
app.MapDelete("/minimal/orders/{id}", (int id) => Results.NoContent());

// Route groups are not resolved: `MapGroup` is not an HTTP verb, so the route
// below is reported at its own registration path, not at /admin/stats.
var admin = app.MapGroup("/admin");
admin.MapGet("/stats", () => Results.Ok(connectionString is not null));

app.Run();

record Order(int Id);
