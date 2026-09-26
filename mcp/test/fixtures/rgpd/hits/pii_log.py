"""rgpd-pii-in-log-py -- every `# BUG` line fires the rule exactly once."""

import logging

logger = logging.getLogger(__name__)
_LOGGER = logging.getLogger("encomendas")


class Registo:
    def __init__(self, log):
        self.logger = log

    def registar(self, user, request, data, email, nif_cliente, customer_iban):
        logger.info("login falhado para %s", email)  # BUG: a plain name
        logging.warning(f"novo utilizador {user.email}")  # BUG: an attribute in an f-string
        self.logger.error("contacto %s", request.POST["telefone"])  # BUG: a request field by key
        _LOGGER.debug("pagamento %s", data.get("iban"))  # BUG: dict.get with the key
        logger.exception("falhou para %s", user.phone_number)  # BUG: logger.exception
        print("cliente", nif_cliente)  # BUG: print is a log sink in a container
        logger.info("iban %(i)s", {"i": customer_iban})  # BUG: a name with a prefix
        logger.info("%s %s", mask_email(email), user.niss)  # BUG: the niss (excluded: the email)
        logger.info("%s %s", customer_iban[-4:], user.email)  # BUG: the email (excluded: last four)
