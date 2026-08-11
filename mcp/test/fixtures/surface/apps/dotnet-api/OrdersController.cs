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

    // ADVERSARIAL. A foreign attribute precedes the route one, so Semgrep's
    // span starts at `Produces(...)`. Anchoring on the first argument list read
    // "application/json" as the path. ASP.NET attribute routes are therefore
    // refused on a redacting Semgrep; none of them appear.
    [Produces("application/json")]
    [HttpGet("/aspnet/orders/{id}")]
    public IActionResult GetOne(int id) => Ok(id);

    // ADVERSARIAL, three decoys at once: anchor text inside a preceding
    // attribute's string, a commented-out old route, and attribute-shaped text
    // in the body. Anchoring by name emitted `/aspnet/orders/legacy`; lexing
    // strings emitted the body's FABRICATED path. Both were `path_partial:
    // false`, i.e. presented as verified URLs.
    [Roles("HttpGet(")]
    // Don't expose this without the guard.
    // [HttpGet("/aspnet/orders/legacy")]
    [HttpGet("/aspnet/orders/audit")]
    public IActionResult Audit() => Ok("it's [HttpGet(\"/aspnet/FABRICATED\")]");

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
