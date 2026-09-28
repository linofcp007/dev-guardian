// rgpd-pii-in-log-js on TypeScript: the same rule, the TypeScript parser.
// Every `// BUG` line fires exactly once.

import { logger } from './logger';

interface Customer {
  id: string;
  nif: string;
  email: string;
  phone_number: string;
}

export function onboard(customer: Customer, customerIban: string): void {
  logger.info(`cliente ${customer.nif}`); // BUG: a typed member in a template literal
  console.error('email invalido', customer.email as string); // BUG: under a type assertion
  logger.warn({ id: customer.id, customerIban }); // BUG: a typed parameter, shorthand
  logger.info('contacto', customer['phone_number']); // BUG: a subscript
}
