import { Controller, Get, Post, Put, Patch, Delete, Body, Param, Query, HttpCode, UseGuards } from '@nestjs/common';
import { AuthGuard } from './auth.guard.js';
import { UsersService } from './users.service.js';

@Controller('users')
export class UsersController {
  constructor(private readonly svc: UsersService) {}

  // N01 BARE decorator, no path — the single most common NestJS form
  @Get()
  findAll(@Query('q') q: string) {
    return this.svc.all(q);
  }

  // N02 bare POST
  @Post()
  @HttpCode(201)
  create(@Body() dto: unknown) {
    return this.svc.create(dto);
  }

  // N03 path argument (control)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.svc.one(id);
  }

  // N04 async + typed return + guard decorator above
  @UseGuards(AuthGuard)
  @Put(':id')
  async replace(@Param('id') id: string, @Body() dto: unknown): Promise<unknown> {
    return this.svc.replace(id, dto);
  }

  // N05 patch with options object second arg
  @Patch(':id/status')
  updateStatus(@Param('id') id: string) {
    return this.svc.status(id);
  }

  // N06 delete, bare
  @Delete()
  purgeAll() {
    return this.svc.purge();
  }

  // N07 array of paths
  @Get(['alias-a', 'alias-b'])
  aliases() {
    return [];
  }
}
