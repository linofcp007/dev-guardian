export default class UsersService {
  private readonly rows = new Map<string, unknown>();

  all(): string[] {
    return [...this.rows.keys()];
  }

  one(id: string): string {
    return id;
  }

  create(body: unknown): unknown {
    return body;
  }

  replace(id: string, body: unknown): unknown {
    this.rows.set(id, body);
    return body;
  }

  touch(id: string): string {
    return id;
  }

  remove(id: string): string {
    this.rows.delete(id);
    return id;
  }
}
