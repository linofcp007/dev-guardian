// rgpd-pii-in-log-js — NOTHING in this file may fire. Each line is the
// correct form, or a near-miss of the shape the rule looks for, and each names
// the clause of the rule that keeps it out.

const logger = require('./logger');

function registo(user, req, email, phone, log, maskedEmail, emailHash, isValidEmail, emailSent, emailService, crypto, formik, repo, settings) {
  console.log(maskEmail(user.email)); // masking helper (pattern-not-inside $MASK(...))
  logger.info('pedido', redact(user.nif)); // masking helper, another name
  logger.info('iban', user.iban.slice(-4)); // last four digits (pattern-not-inside $S.slice(-$N))
  console.log(maskedEmail, emailHash, isValidEmail, emailSent, emailService); // names that are not the value
  console.log('email enviado'); // the word inside a string is not a value
  logger.info({ email: '[redacted]' }); // a key whose value is a literal
  logger.info('utilizador', user.id); // an internal id is the right thing to log
  logger.info('pedido', req.body['orderId']); // a subscript whose key is not personal data ($KEY regex)
  console.log(crypto.createHash('sha256').update(user.email).digest('hex')); // a hash (derived-value guard)
  console.log(user.email.length); // a length ($X.length)
  console.log(!!user.email, !email); // a boolean (!$X)
  console.log(formik.errors.email); // a form's error message for the field ($OBJ regex)
  logger.info('existe', repo.exists({ email })); // a predicate's boolean (derived-value guard)
  console.log(settings.DEFAULT_FROM_EMAIL); // a setting: an all-caps member with an underscore
  log.push(email); // an ARRAY named log: not a logging method ($METHOD regex)
  Math.log(phone); // not a logger ($LOGGER regex)
  analytics.track('signup', { plan: user.plan }); // not a logger either
  sendEmail(email); // not a log call at all
  const params = new URLSearchParams(req.url);
  logger.debug('pagina', params.get('page')); // a .get() whose key is not personal data
}

module.exports = { registo };
