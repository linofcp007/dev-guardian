import { Controller, Get } from '@nestjs/common';

@Controller()
export class RootController {
  // N10 arrow-property handler (not a method) — does the `$M(...) { ... }` tail match?
  @Get('arrow')
  handle = () => 'x';

  // N11 method with expression body via return only, single-line braces
  @Get('oneline') short() { return 1; }
}
