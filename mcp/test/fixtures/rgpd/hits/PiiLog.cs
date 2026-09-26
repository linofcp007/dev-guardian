// rgpd-pii-in-log-cs -- every `// BUG` line fires the rule exactly once.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Serilog;

public class Registo
{
    private readonly ILogger<Registo> _logger;
    private readonly log4net.ILog _log;

    public Cliente Cliente { get; set; } = new();

    public Registo(ILogger<Registo> logger, log4net.ILog log)
    {
        _logger = logger;
        _log = log;
    }

    public void Registar(Cliente cliente, string email, string nifCliente, IDictionary<string, string> form, Mensagem mensagem)
    {
        _logger.LogInformation("Login {Email}", cliente.Email); // BUG: structured argument
        _logger.LogWarning($"NIF {cliente.Nif}"); // BUG: interpolated string
        Console.WriteLine("sms para " + cliente.PhoneNumber); // BUG: Console.WriteLine
        Log.Information("Pagamento {Iban}", cliente.Iban); // BUG: Serilog's static Log
        _logger.LogError("Cliente {Nif}", nifCliente); // BUG: a camelCase pt-PT name
        _log.Info("registo " + email); // BUG: log4net
        _logger.LogDebug("Form {V}", form["telefone"]); // BUG: a request field by key
        Debug.WriteLine(cliente.NormalizedEmail); // BUG: ASP.NET Identity's NormalizedEmail is the email
        _logger.LogInformation("{E}", Cliente.Email); // BUG: a PascalCase PROPERTY is not a type — only an all-caps member of one is a constant
        _logger.LogInformation("{N} {I}", cliente.NIF, cliente.IBAN); // BUG x2: all-caps properties are the value
        _logger.LogInformation("{A} {B}", Mask(cliente.Email), cliente.Niss); // BUG: the Niss (excluded: the email)
        _logger.LogInformation("{A} {B}", cliente.Iban[^4..], cliente.Email); // BUG: the email (excluded: last four)
        _logger.LogInformation("Normalizado {E}", email.ToLowerInvariant()); // BUG: a METHOD call on the name still returns the address
        _logger.LogInformation("Para {E}", mensagem.Email.Address); // BUG: a NEUTRAL attribute of the value still holds it (the $ATTR name list)
    }

    private static string Mask(string value) => new string('*', value.Length);
}

public class Mensagem
{
    public System.Net.Mail.MailAddress Email { get; set; } = new("a@b.pt");
}

public class Cliente
{
    public string Email { get; set; } = "";
    public string NormalizedEmail { get; set; } = "";
    public string Nif { get; set; } = "";
    public string Niss { get; set; } = "";
    public string Iban { get; set; } = "";
    public string PhoneNumber { get; set; } = "";
    public string NIF { get; set; } = "";
    public string IBAN { get; set; } = "";
}
