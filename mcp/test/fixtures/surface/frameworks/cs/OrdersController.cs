using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using static System.Math;
global using System.Text.Json;
using Json = System.Text.Json.JsonSerializer;

namespace Api;

[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    // C01 control: attribute with a literal path
    [HttpGet("all")]
    public IActionResult All() { return Ok(); }

    // C02 BARE attribute — path comes from the class [Route]. Very common.
    [HttpGet]
    public IActionResult Index() { return Ok(); }

    // C03 bare + separate [Route]
    [HttpPost]
    [Route("submit")]
    public IActionResult Submit() { return Ok(); }

    // C04 expression-bodied action (no braces)
    [HttpGet("quick")]
    public IActionResult Quick() => Ok();

    // C05 async task return
    [HttpPut("{id:int}")]
    public async Task<IActionResult> Replace(int id) { await Task.Yield(); return Ok(); }

    // C06 named Name= argument
    [HttpDelete("{id}", Name = "RemoveOrder")]
    public IActionResult Remove(int id) { return Ok(); }

    // C07 patch, control
    [HttpPatch("{id}/status")]
    public IActionResult Status(int id) { return Ok(); }
}
