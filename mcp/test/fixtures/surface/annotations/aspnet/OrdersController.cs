// ASP.NET attribute routing in the style `dotnet new webapi` emits.
//
// Written by the auditor of `configs/semgrep/routes.yml`, not by the author of
// the rules it exercises. Measured against the pack as shipped, a controller
// written this way reported ZERO routes — a C# API described as exposing
// nothing at all — because every attribute rule demanded an argument that the
// bare `[HttpGet]` form does not supply, and the class-level
// `[Route("api/[controller]")]` holds the path instead.
//
// SYSTEMATIC BY DESIGN. Each of the five verb attributes appears in all three
// forms, because each is a separate pattern alternative in routes.yml and an
// alternative no fixture exercises is a clause nobody can tell is dead:
//
//   [HttpGet("p")]            the path on the attribute (always worked)
//   [HttpGet] + [Route("p")]  the path on a companion attribute
//   [HttpGet]                 bare, path inherited from the class
//
// Deleting any single alternative from the pack — including the `pattern-not`
// that stops the bare rule from ALSO claiming the [Route] methods — must turn
// exactly one row of the expected set red.

using Microsoft.AspNetCore.Mvc;

namespace Api;

[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    // ---- GET ----
    [HttpGet("all")]
    public IActionResult All() { return Ok(); }

    [HttpGet]
    [Route("get-named")]
    public IActionResult GetNamed() { return Ok(); }

    // The scaffold's own index action.
    [HttpGet]
    public IActionResult Index() { return Ok(); }

    // ---- POST ----
    [HttpPost("post-attr")]
    public IActionResult PostAttr() { return Ok(); }

    [HttpPost]
    [Route("submit")]
    public IActionResult Submit() { return Ok(); }

    // Empty parens: the same pattern as the bare form, to Semgrep.
    [HttpPost()]
    public IActionResult EmptyParens() { return Ok(); }

    // ---- PUT ----
    [HttpPut("put-attr")]
    public IActionResult PutAttr() { return Ok(); }

    // The companion attribute written BEFORE the verb one. Semgrep matches it
    // with the same alternative, so there is no reversed twin in the pack.
    [Route("before")]
    [HttpPut]
    public IActionResult Before() { return Ok(); }

    [HttpPut]
    public async Task<IActionResult> ReplaceAll() { await Task.Yield(); return Ok(); }

    // ---- PATCH ----
    [HttpPatch("{id}/status")]
    public IActionResult Status(int id) { return Ok(id); }

    [HttpPatch]
    [Route("patch-named")]
    public IActionResult PatchNamed() { return Ok(); }

    // Bare, expression-bodied action.
    [HttpPatch]
    public IActionResult Quick() => Ok();

    // ---- DELETE ----
    // The multi-argument form, which never stopped working.
    [HttpDelete("{id}", Name = "RemoveOrder")]
    public IActionResult Remove(int id) { return Ok(id); }

    [HttpDelete]
    [Route("delete-named")]
    public IActionResult DeleteNamed() { return Ok(); }

    // Bare, async, and inside a combined attribute list.
    [ApiExplorerSettings(IgnoreApi = true), HttpDelete]
    public async Task<IActionResult> Wipe() { await Task.Yield(); return Ok(); }
}
