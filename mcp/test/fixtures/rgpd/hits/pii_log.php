<?php
// rgpd-pii-in-log-php — every `// BUG` line fires the rule exactly once.
// WordPress/WooCommerce shapes first, because that is where PHP logs PII.

class Encomendas
{
    private $logger;

    public function registar($user, $order, $email, $nif_cliente, $telefone, array $data, $cliente): void
    {
        error_log('login falhado para ' . $email); // BUG: a plain variable
        error_log("novo registo {$user->user_email}"); // BUG: WP_User::$user_email, interpolated
        error_log("cliente $nif_cliente"); // BUG: a variable interpolated in a string
        $this->logger->warning('contacto ' . $_POST['telefone']); // BUG: a request field by key
        wc_get_logger()->debug('encomenda ' . $order->get_billing_email()); // BUG: WooCommerce getter
        Log::info('pagamento', ['iban' => $data['iban']]); // BUG: Laravel's facade
        syslog(LOG_INFO, 'sms para ' . $order->get_billing_phone()); // BUG: syslog
        error_log(print_r(['nif' => $user->nif], true)); // BUG: a dump of an array holding it
        $this->logger->info('registo', ['cliente' => $nif_cliente]); // BUG: a variable in PSR-3 context
        Log::withContext(['utilizador' => $email]); // BUG: shared context lands on every later line
        syslog(LOG_WARNING, "contacto $telefone"); // BUG: a variable interpolated into syslog
        error_log('nif ' . $cliente->NIF); // BUG: an all-caps property is the value
        \Illuminate\Support\Facades\Log::info('registo', ['e' => $email]); // BUG: the fully-qualified facade
        Log::channel('stack')->info('registo', ['e' => $email]); // BUG: a Laravel log channel
        logger()->info('registo', ['e' => $email]); // BUG: Laravel's logger() helper
        logger('registo', ['e' => $email]); // BUG: logger() called directly logs at debug level
        error_log(md5($email) . ' ' . $user->niss); // BUG: the niss is whole (excluded: the hashed email)
        error_log(substr($data['iban'], -4) . ' ' . $email); // BUG: the email is whole (excluded: last four)
    }
}
