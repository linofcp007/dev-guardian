// ASP.NET class-level routes and route tokens: every shape the join in
// `mcp/src/surface/resolvers/classPrefix.ts` decides, one controller each.
//
// A route here is RESOLVED only when its controller is concrete and declares
// exactly one literal [Route] of its own — or when the method path is rooted
// (`/x`, `~/x`), which ignores the class route — and every token in the
// combined template can be named: `[controller]` the class name less its
// `Controller` suffix, `[action]` the method name less an `Async` suffix.
// Everything else stays partial at the path the method names. Each class is
// also the fixture of one guard of the `guardian-scope-aspnet-*` rules.

using Microsoft.AspNetCore.Mvc;

namespace Api.Prefixes;

// [Route("api/commented")] — a comment, never a prefix.
[ApiController]
[Route("api/[controller]/[action]")]
public class ReportsController : ControllerBase
{
    // /api/Reports/Summary — a bare attribute is served AT the template.
    [HttpGet]
    public IActionResult Summary() { return Ok(); }

    // /api/Reports/Detail/{id} — `Async` is not part of the action name.
    [HttpGet("{id}")]
    public async Task<IActionResult> DetailAsync(int id) { await Task.Yield(); return Ok(id); }

    // [ActionName] renames the action: partial, never /api/Reports/Original.
    [HttpPost]
    [ActionName("renamed")]
    public IActionResult Original() { return Ok(); }

    // Rooted: the class route is ignored, the token still replaced.
    [HttpGet("/rooted/[controller]")]
    public IActionResult Rooted() { return Ok(); }

    // `~/` roots it too: /legacy/reports.
    [HttpGet("~/legacy/reports")]
    public IActionResult Legacy() { return Ok(); }

    // A local function is a method of its own: the action is Compute.
    [HttpGet("calc")]
    public IActionResult Compute()
    {
        int Inner(int y) { return y; }
        return Ok(Inner(1));
    }
}

// Two class routes: every action is served twice. Partial.
[Route("api/v1/[controller]")]
[Route("api/v2/[controller]")]
public class MultiController : ControllerBase
{
    [HttpGet("m")]
    public IActionResult M() { return Ok(); }
}

// A constant route: its value is not in this file. Partial.
[Route(Routes.Admin)]
public class ConstController : ControllerBase
{
    [HttpGet("c")]
    public IActionResult C() { return Ok(); }
}

// [area] is an [Area] attribute this pack does not read. Partial.
[Area("admin")]
[Route("[area]/[controller]")]
public class AreaController : Controller
{
    [HttpGet("a")]
    public IActionResult A() { return Ok(); }
}

// An abstract base: no controller of its own. Its relative route is served
// under each derived controller, `[controller]` being THAT class's name, so
// partial; a rooted one is the same URL whoever serves it.
[ApiController]
[Route("api/[controller]")]
public abstract class BaseApiController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping() { return Ok(); }

    [HttpGet("/rooted-ping")]
    public IActionResult RootedPing() { return Ok(); }
}

// No [Route] of its own: MVC uses the first base class that has one, which
// this file cannot show. Partial.
public class NoRouteController : BaseApiController
{
    [HttpGet("x")]
    public IActionResult X() { return Ok(); }
}

// [ControllerName] renames the `[controller]` token. Partial.
[Route("api/renamed/[controller]")]
[ControllerName("Custom")]
public class RenamedController : ControllerBase
{
    [HttpGet("r")]
    public IActionResult R() { return Ok(); }
}

// Nesting: each route belongs to the innermost class around it.
[Route("api/outer")]
public class OuterController : ControllerBase
{
    // /api/outer/o
    [HttpGet("o")]
    public IActionResult O() { return Ok(); }

    // No [Route] of its own: partial, and never /api/outer/n.
    public class Nested
    {
        [HttpGet("n")]
        public IActionResult N() { return Ok(); }
    }

    // A controller of its own, with its own route: /api/inner/i.
    [Route("api/inner")]
    public class InnerController : ControllerBase
    {
        [HttpGet("i")]
        public IActionResult I() { return Ok(); }
    }
}
