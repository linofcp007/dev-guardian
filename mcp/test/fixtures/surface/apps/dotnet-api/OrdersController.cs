using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Demo.Controllers;

[ApiController]
[Route("api/orders")]
public class OrdersController : ControllerBase
{
    [HttpGet("/aspnet/orders")]
    public IActionResult List() => Ok();

    // No argument: nothing to capture, so no route is reported for it.
    [HttpGet]
    public IActionResult Index()
    {
        return Ok();
    }

    // A non-route attribute PRECEDING the route one. Semgrep's span starts at
    // `Produces(...)`, so recovery anchored on the first argument list reads
    // "application/json" as the path — a RESOLVED route that exists nowhere.
    // The capture has to be anchored on `HttpGet(` by name.
    [Produces("application/json")]
    [HttpGet("/aspnet/orders/{id}")]
    public IActionResult GetOne(int id) => Ok(id);

    [HttpPost("/aspnet/orders")]
    public async Task<IActionResult> Create()
    {
        await Task.Yield();
        return Ok();
    }

    [HttpPut("/aspnet/orders/{id}")]
    [Authorize]
    public IActionResult Replace(int id)
    {
        return Ok(id);
    }

    [HttpPatch("/aspnet/orders/{id}/status")]
    public IActionResult Status(int id) => Ok(id);

    [HttpDelete("/aspnet/orders/{id}")]
    public IActionResult Remove(int id)
    {
        return NoContent();
    }
}
