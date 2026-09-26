"""rgpd-pii-in-log-py -- NOTHING in this file may fire. Each line names the
clause of the rule that keeps it out."""

import logging
import math

from django.core.management.base import BaseCommand

logger = logging.getLogger(__name__)


def registar(user, data, email, masked_email, log, audit, settings):
    logger.info("login falhado para %s", mask_email(email))  # masking helper
    logger.info("pedido %s", redact(user.nif))  # masking helper, another name
    logger.info("iban %s", data["iban"][-4:])  # last four digits
    logger.info("email enviado para %s", masked_email)  # a masked name
    logger.info("utilizador %s", user.id)  # an internal id is the right thing to log
    logger.info("pedido %s", data["pedido_id"])  # a subscript whose key is not personal data ($KEY regex)
    logger.info("tamanho %s", len(email))  # a length (derived-value guard)
    logger.info("de %s", settings.DEFAULT_FROM_EMAIL)  # a setting: an all-caps attribute with an underscore
    logger.info("campo %s", Campo.EMAIL)  # a class constant: an all-caps attribute of a CapWords receiver
    logger.info("pedido", extra={"pedido_id": data["pedido_id"]})  # a keyword argument that is not personal data
    logger.info("pedido %s", data.get("pedido_id"))  # a key that is not personal data
    log.append(email)  # a LIST named log: not a logging method ($METHOD regex)
    audit.info(email)  # not a logger ($LOGGER regex)
    math.log(len(email))  # math, not logging
    send_mail(email, "Assunto", "Corpo")  # not a log call at all


def agendar(email, dados):
    # `email` here is a scheduled-message OBJECT: what reaches the log is its id
    # and its date, read as attributes (attribute-read guard). Real shape, from
    # an application corpus, rewritten.
    logger.warning("mensagem %s agendada para %s sem destinatarios", email.id, email.enviar_em)
    # The address is a LOOKUP KEY: what is logged is the id of the result.
    logger.info("mapa de ids: %s", obter_bot(dados["email"], 1).id)


class Command(BaseCommand):
    # A Django management command: its output goes to the terminal of the
    # operator who ran it, the same channel as `self.stdout.write`, which the
    # rule never read as a log (the `class Command` guard on the print sink).
    def handle(self, *args, **options):
        utilizador = obter_utilizador(options["email"])
        print(f"Desativado: {utilizador.email}")
        self.resumo(utilizador.email)

    def resumo(self, email):
        print("sessoes ativas de", email)
