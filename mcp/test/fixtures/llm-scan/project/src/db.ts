export interface Row {
  [column: string]: unknown;
}

const pool = {
  async execute(sql: string, params: unknown[]): Promise<Row[]> {
    return [{ sql, params }];
  },
};

export async function query(sql: string, params: unknown[]): Promise<Row[]> {
  return pool.execute(sql, params);
}
