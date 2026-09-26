// rgpd-pii-in-log-cs -- NOTHING in this file may fire. Each line names the
// clause of the rule that keeps it out.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

public class Registo
{
    private readonly ILogger<Registo> _logger;
    private readonly Metrics _metrics = new();

    public Registo(ILogger<Registo> logger) => _logger = logger;

    public void Registar(Cliente cliente, string email, string maskedEmail, IDictionary<string, string> form)
    {
        _logger.LogInformation("Pedido {P}", form["pedido"]); // a key that is not personal data ($KEY regex)
        _logger.LogInformation("Login {E}", MaskEmail(cliente.Email)); // masking helper
        _logger.LogInformation("Iban {I}", cliente.Iban[^4..]); // last four digits
        _logger.LogInformation("Email enviado {E}", maskedEmail); // a masked name
        _logger.LogInformation("Confirmado {C}", cliente.EmailConfirmed); // a flag, not the value
        _logger.LogInformation("Cliente {Id}", cliente.Id); // an internal id is the right thing to log
        Debug.Assert(email.Length > 0); // not a logging method ($METHOD regex)
        _metrics.Info(email); // not a logger ($LOGGER regex)
        Console.WriteLine(Math.Log(2)); // math, not personal data
    }

    private static string MaskEmail(string value) => "***" + value[^4..];
}

public class Metrics
{
    public void Info(string value) { }
}

public class Cliente
{
    public int Id { get; set; }
    public string Email { get; set; } = "";
    public bool EmailConfirmed { get; set; }
    public string Iban { get; set; } = "";
}
