import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
  Put,
} from '@nestjs/common';

import UsersService from './users.service.js';

@Controller('users')
export class UsersController {
  constructor(private readonly service: UsersService) {}

  // No argument: there is no path to capture, so the pack does not report it.
  // The controller prefix ('users') is not resolvable from the decorator alone.
  @Get()
  findAll(): string[] {
    return this.service.all();
  }

  @Get(':id')
  findOne(@Param('id') id: string): string {
    return this.service.one(id);
  }

  @Post('/create')
  async create(@Body() body: unknown): Promise<unknown> {
    return this.service.create(body);
  }

  @Put(':id')
  replace(@Param('id') id: string, @Body() body: unknown): unknown {
    return this.service.replace(id, body);
  }

  @Patch(':id/status')
  update(@Param('id') id: string): string {
    return this.service.touch(id);
  }

  @Delete(':id')
  remove(@Param('id') id: string): string {
    return this.service.remove(id);
  }

  // ADVERSARIAL. A foreign decorator precedes the route one, so Semgrep's span
  // starts at `@HttpCode(...)`. Anchoring on the first argument list read `204`
  // as the path. NestJS routes are refused on a redacting Semgrep; none appear.
  @HttpCode(204)
  @Delete('purge/:id')
  purge(@Param('id') id: string): string {
    return this.service.remove(id);
  }

  // ADVERSARIAL: a commented-out old route, an apostrophe in the comment, and
  // decorator-shaped text in the body. Anchoring by name emitted `legacy/:id`;
  // lexing strings emitted `audit/FABRICATED`.
  @HttpCode(200)
  // Don't expose this without the guard.
  // @Get('legacy/:id')
  @Get('audit/:id')
  audit(@Param('id') id: string): string {
    return `it's @Get('audit/FABRICATED') for ${id}`;
  }
}
