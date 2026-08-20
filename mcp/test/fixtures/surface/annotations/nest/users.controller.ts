/**
 * NestJS controller in the framework's OWN documented style.
 *
 * Written by the auditor of `configs/semgrep/routes.yml`, not by the author of
 * the rules it exercises — which is the whole point of this tree. Every
 * fixture under `../apps/` was written alongside the rule that reads it, so
 * each rule was only ever tried against the syntax it was written for: there
 * was not one `@Get()` anywhere in the repository, and `@Get()` is the form
 * docs.nestjs.com uses for the index and create actions of every controller in
 * its own examples. Three of a seven-decorator controller's routes matched
 * NOTHING before the bare-decorator rules existed, silently — a route this
 * pack misses produces no error anywhere.
 *
 * SYSTEMATIC BY DESIGN: all five verbs appear bare AND with a path, because
 * each bare rule is a separate rule in the pack and one no fixture exercises
 * is a rule nobody can tell is dead. Deleting any one of them must turn
 * exactly one row of the expected set red.
 *
 * `@Get()` and `@Get('')` are indistinguishable once extracted: both are an
 * empty own-path, reported partial. Both are here because they are different
 * SOURCE forms and one of them used to match while the other did not.
 */

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
  Query,
  UseGuards,
} from '@nestjs/common';

import { AuthGuard } from './auth.guard.js';
import UsersService from './users.service.js';

@Controller('users')
export class UsersController {
  constructor(private readonly svc: UsersService) {}

  // The single most common NestJS form: no argument at all. The served path is
  // the controller prefix, which nothing here can resolve — so the route is
  // reported with an empty own-path and `path_partial: true`, never dropped.
  @Get()
  findAll(@Query('q') q: string): string[] {
    return this.svc.all(q);
  }

  // Control: a path argument, which always worked.
  @Get(':id')
  findOne(@Param('id') id: string): string {
    return this.svc.one(id);
  }

  // The explicitly-empty path. Distinct source form, same extracted record.
  @Get('')
  empty(): string[] {
    return [];
  }

  // Bare POST, with a second decorator between it and the method.
  @Post()
  @HttpCode(201)
  create(@Body() dto: unknown): unknown {
    return this.svc.create(dto);
  }

  @Post('bulk')
  createMany(@Body() dto: unknown): unknown {
    return this.svc.create(dto);
  }

  // Bare decorator under a foreign one that takes an argument — the shape that
  // made unfocused recovery read `AuthGuard` as a path.
  @UseGuards(AuthGuard)
  @Put()
  replaceAll(@Body() dto: unknown): unknown {
    return this.svc.replaceAll(dto);
  }

  @Put(':id')
  replace(@Param('id') id: string, @Body() dto: unknown): unknown {
    return this.svc.replace(id, dto);
  }

  @Patch()
  touchAll(): string {
    return this.svc.touchAll();
  }

  @Patch(':id/status')
  status(@Param('id') id: string): string {
    return this.svc.status(id);
  }

  // Bare DELETE on an async method.
  @Delete()
  async purgeAll(): Promise<void> {
    await this.svc.purge();
  }

  @Delete(':id')
  remove(@Param('id') id: string): string {
    return this.svc.remove(id);
  }

  // An arrow-property handler rather than a method, bare.
  @Get()
  ping = (): string => 'pong';

  // NOT a route: a method whose NAME is a decorator name. If this ever appears
  // in the extracted set, the bare rules are matching call expressions.
  notARoute(): string {
    return this.svc.Get();
  }
}
