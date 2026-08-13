// Fixture for guardian-import-csharp's aliased form, which neither
// Program.cs nor OrdersController.cs exercises (both only use plain `using`).
using Json = System.Text.Json.JsonSerializer;

namespace Demo
{
    internal static class JsonHelper
    {
        internal static string ToJson(object value) => Json.Serialize(value);
    }
}
