"""rgpd-pii-in-log-py -- NOTHING in this file may fire. Each line names the
clause of the rule that keeps it out."""

import logging
import math

logger = logging.getLogger(__name__)


def registar(user, data, email, masked_email, log, audit):
    logger.info("login falhado para %s", mask_email(email))  # masking helper
    logger.info("pedido %s", redact(user.nif))  # masking helper, another name
    logger.info("iban %s", data["iban"][-4:])  # last four digits
    logger.info("email enviado para %s", masked_email)  # a masked name
    logger.info("utilizador %s", user.id)  # an internal id is the right thing to log
    logger.info("pedido %s", data["pedido_id"])  # a subscript whose key is not personal data ($KEY regex)
    logger.info("pedido %s", data.get("pedido_id"))  # a key that is not personal data
    log.append(email)  # a LIST named log: not a logging method ($METHOD regex)
    audit.info(email)  # not a logger ($LOGGER regex)
    math.log(len(email))  # math, not logging
    send_mail(email, "Assunto", "Corpo")  # not a log call at all
