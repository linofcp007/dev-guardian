// ASP.NET verb attributes with NAMED arguments — `Name = …`, `Order = …` and
// the template passed as `template: …`.
//
// The first controller is `dotnet new webapi`'s scaffold as it emits it: its
// one endpoint is `[HttpGet(Name = "GetWeatherForecast")]`, and on 3.6.1 it
// was matched by no rule at all — the bare rules took `[HttpGet]` and
// `[HttpGet()]` only, the path rules a positional path only — so the
// controller reported nothing.
//
// The second is systematic, one verb per block, because each shape decides a
// different clause of a different rule in `configs/semgrep/routes.yml`:
//
//   [HttpGet(Name = "x")]            the bare rule's named alternative
//   [HttpGet("p", Name = "x")]       its positional-path `pattern-not`: the
//                                    path rule's, at "p", never "Name = …"
//   [HttpGet(template: "p")]         its `template:` `pattern-not`, and the
//                                    path rule's `template:` alternative
//
// Every verb carries all three, so deleting any one clause from any one of the
// ten rules turns a row of the expected set red (or adds one).

using Microsoft.AspNetCore.Mvc;

namespace Api.Named;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(ILogger<WeatherForecastController> logger)
    {
        _logger = logger;
    }

    // GET /WeatherForecast
    [HttpGet(Name = "GetWeatherForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast()).ToArray();
    }
}

[ApiController]
[Route("api/[controller]")]
public class NamedArgsController : ControllerBase
{
    // ---- GET ----
    // Two named arguments, no path: served at the controller's route.
    [HttpGet(Name = "ListNamed", Order = 2)]
    public IActionResult List() { return Ok(); }

    [HttpGet("{id}", Name = "GetById")]
    public IActionResult ById(int id) { return Ok(id); }

    [HttpGet(template: "get-template")]
    public IActionResult GetTemplate() { return Ok(); }

    // A Name beside a [Route]: two selectors to ASP.NET — this one at the
    // controller's route (the attribute is not "silent": it has a Name), and
    // `[Route("companion")]` with no verb, which no rule reports.
    [HttpGet(Name = "WithCompanion")]
    [Route("companion")]
    public IActionResult WithCompanion() { return Ok(); }

    // ---- POST ----
    // `Order` alone, and an expression-bodied action.
    [HttpPost(Order = 1)]
    public IActionResult Create() => Ok();

    [HttpPost("post-named", Name = "PostNamed")]
    public IActionResult PostNamed() { return Ok(); }

    [HttpPost(template: "post-template")]
    public IActionResult PostTemplate() { return Ok(); }

    // ---- PUT ----
    // A named argument from a nameof, async.
    [HttpPut(Name = nameof(Replace))]
    public async Task<IActionResult> Replace() { await Task.Yield(); return Ok(); }

    [HttpPut("{id}", Order = 1)]
    public IActionResult PutById(int id) { return Ok(id); }

    // The template by name, then another named argument.
    [HttpPut(template: "put-template", Name = "PutTemplate")]
    public IActionResult PutTemplate() { return Ok(); }

    // ---- PATCH ----
    // In a combined attribute list, after an unrelated attribute's own named
    // argument.
    [ApiExplorerSettings(IgnoreApi = true), HttpPatch(Name = "PatchNamed")]
    public IActionResult Touch() { return Ok(); }

    [HttpPatch("{id}/flag", Name = "PatchFlag")]
    public IActionResult Flag(int id) { return Ok(id); }

    // The template by name AFTER a named argument: matched all the same.
    [HttpPatch(Name = "PatchTemplate", template: "patch-template")]
    public IActionResult PatchTemplate() { return Ok(); }

    // ---- DELETE ----
    // (`[HttpDelete("{id}", Name = "RemoveOrder")]` is in OrdersController.cs.)
    [HttpDelete(Order = 2)]
    public IActionResult Purge() { return Ok(); }

    [HttpDelete("{id}/hard", Name = "HardDelete")]
    public IActionResult Hard(int id) { return Ok(id); }

    [HttpDelete(template: "delete-template")]
    public IActionResult DeleteTemplate() { return Ok(); }
}
