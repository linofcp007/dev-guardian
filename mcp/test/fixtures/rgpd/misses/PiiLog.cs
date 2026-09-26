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
        _logger.LogInformation("Campo {C}", Campos.EMAIL); // a constant of a static class: an all-caps member of a PascalCase type name
        _logger.LogInformation("Login {E}", MaskEmail(cliente.Email)); // masking helper
        _logger.LogInformation("Iban {I}", cliente.Iban[^4..]); // last four digits
        _logger.LogInformation("Email enviado {E}", maskedEmail); // a masked name
        _logger.LogInformation("Confirmado {C}", cliente.EmailConfirmed); // a flag, not the value
        _logger.LogInformation("Cliente {Id}", cliente.Id); // an internal id is the right thing to log
        Debug.Assert(email != null); // not a logging method ($METHOD regex; this line was `email.Length > 0` until the attribute-read guard took that shape too, and the regex read DEAD)
        _metrics.Info(email); // not a logger ($LOGGER regex)
        Console.WriteLine(Math.Log(2)); // math, not personal data
        _logger.LogInformation("Tamanho {T}", email.Length); // a length: a property read on the value (attribute-read guard)
    }

    // `email` is a queued-message OBJECT: what reaches the log is its id and its
    // date, read as properties; and an address used as a LOOKUP KEY, where what
    // is logged is the id of the result (attribute-read guard).
    public void Agendar(MensagemAgendada email, IDictionary<string, string> form)
    {
        _logger.LogWarning("Mensagem {Id} agendada para {Data} sem destinatarios", email.Id, email.EnviarEm);
        _logger.LogInformation("Mapa de ids {Id}", ObterBot(form["email"]).Id);
    }

    private static Cliente ObterBot(string endereco) => new();

    private static string MaskEmail(string value) => "***" + value[^4..];
}

public class MensagemAgendada
{
    public int Id { get; set; }
    public DateTime EnviarEm { get; set; }
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
