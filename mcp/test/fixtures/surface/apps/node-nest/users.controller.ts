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

  // A non-route decorator PRECEDING the route one. Semgrep's span starts at
  // `@HttpCode(...)`, so recovery anchored on the first argument list reads
  // `204` as the path — and a bare lower-case/numeric word passes the literal
  // test, so it is emitted as a RESOLVED route. The capture has to be anchored
  // on `@Delete(` by name.
  @HttpCode(204)
  @Delete('purge/:id')
  purge(@Param('id') id: string): string {
    return this.service.remove(id);
  }
}
