// rgpd-pii-in-log-js — every `// BUG` line fires the rule exactly once, and
// the two `// BUG x2` lines exactly twice. Deliberately personal data, all
// fictitious. Lines marked `// excluded:` carry a guard shape BESIDE a bug, so
// an exclusion keyed one notch too wide has somewhere to show.

const logger = require('./logger');
const winston = require('winston');

function registo(user, users, req, email, nif_cliente, clienteNif, formData, cliente) {
  console.log('login', email); // BUG: a plain identifier
  console.info(`novo utilizador ${user.email}`); // BUG: a member inside a template literal
  logger.info({ email }); // BUG: object shorthand
  logger.warn('contacto', { telefone: req.body.telefone }); // BUG: a nested member
  logger.error('pagamento falhou', req.body['iban']); // BUG: a subscript with a string key
  logger.debug('pesquisa', formData.get('nif')); // BUG: a Map/FormData/URLSearchParams read
  this.logger.info('sms enviado para ' + user.phoneNumber); // BUG: `this.logger`, concatenation
  req.log.info({ niss: user.niss }); // BUG: fastify's request logger
  console.log(nif_cliente, clienteNif); // BUG x2: pt-PT snake_case and camelCase names
  console.log(users.map((u) => u.cartao_cidadao)); // BUG: inside a callback in the call
  console.log(user?.email); // BUG: optional chaining
  winston.info(user.getEmail()); // BUG: a getter
  console.log(cliente.NIF, cliente.IBAN); // BUG x2: an all-caps member is the value, not a constant
  console.log(truncate(user.email, 30)); // BUG: truncating is not masking
  Logger.log(user.email); // BUG: NestJS's static Logger
  logger.child({ email }); // BUG: a pino child logger stamps it on every later line
  this.hashing.logger.info('registo', user.email); // BUG: "hash" in the RECEIVER path is not a masking call
  console.log(mask(user.email), user.nif); // BUG: the nif is not masked (excluded: the email)
  console.log(user.iban.slice(-4), user.email); // BUG: the email is whole (excluded: last four of the IBAN)
}

module.exports = { registo };
