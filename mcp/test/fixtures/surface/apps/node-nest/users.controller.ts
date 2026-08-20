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

  // No argument: there is no path to capture, and this is the form NestJS's
  // own docs use for an index action. The route is reported with an EMPTY
  // own-path at path_partial: true — the controller prefix ('users') is not
  // resolvable from the decorator alone, but the endpoint exists. Reporting
  // nothing (the behaviour this comment used to describe as a design) meant a
  // real controller silently lost every collection endpoint it has. See
  // ../../annotations/ for the fixture that measures this properly.
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

  // ADVERSARIAL. A foreign decorator precedes the route one, so an unfocused
  // rule's span starts at `@HttpCode(...)` — anchoring on the first argument
  // list read `204` as the path. The rule focuses on $PATH, so the reported
  // range is the literal and `purge/:id` is what comes back. `204` must never
  // appear as a route.
  @HttpCode(204)
  @Delete('purge/:id')
  purge(@Param('id') id: string): string {
    return this.service.remove(id);
  }

  // ADVERSARIAL: a commented-out old route, an apostrophe in the comment, and
  // decorator-shaped text in the body. Anchoring by name emitted `legacy/:id`;
  // lexing strings emitted `audit/FABRICATED`. Neither is reachable from a span
  // that is just the path literal — the expected route is `audit/:id`.
  @HttpCode(200)
  // Don't expose this without the guard.
  // @Get('legacy/:id')
  @Get('audit/:id')
  audit(@Param('id') id: string): string {
    return `it's @Get('audit/FABRICATED') for ${id}`;
  }
}
