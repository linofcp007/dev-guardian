<?php
// rgpd-pii-in-log-php — NOTHING in this file may fire. Each line names the
// clause of the rule that keeps it out.

class Encomendas
{
    private $logger;
    private \SplQueue $log;

    public function registar($user, $order, $email, $masked_email, array $data): void
    {
        error_log('login falhado para ' . mask_email($email)); // masking helper
        error_log('hash ' . wp_hash($user->user_email)); // hashing helper
        error_log('iban ' . substr($data['iban'], -4)); // last four digits
        error_log('email enviado para ' . $masked_email); // a masked name
        error_log('utilizador ' . $user->ID); // an internal id is the right thing to log
        error_log('pedido ' . $data['pedido_id']); // a key that is not personal data ($KEY regex)
        error_log('tamanho ' . strlen($email)); // a length (derived-value guard)
        $this->logger->info('encomenda ' . $order->get_id()); // not personal data
        $this->log->push($email); // not a PSR-3 level ($METHOD regex)
        $this->mailer->info($email); // not a logger ($LOGGER regex)
        Cache::info($email); // not the Log facade ($FACADE regex)
        $total = log($data['valor']); // math, not logging
        wp_mail($email, 'Assunto', 'Corpo'); // not a log call at all
    }
}
