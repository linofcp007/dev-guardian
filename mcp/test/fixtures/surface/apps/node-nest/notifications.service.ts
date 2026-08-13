// Fixture for guardian-import-esm's namespace-import form
// (`import * as ns from "..."`), which neither users.controller.ts nor
// users.service.ts exercises.
import * as templates from './templates.js';

export class NotificationsService {
  render(name: string): string {
    return templates.lookup(name);
  }
}
