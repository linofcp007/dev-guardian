export async function handler(repo: { save(v: unknown): Promise<void> }): Promise<string> {
  repo.save({ id: 1 });
  return 'ok';
}

// Assignment-form async arrow — the shape `async function $F(...) { ... }`
// alone cannot match (bugfix-rules-jsts fix wave; see the rule's own comment).
export const arrowHandler = async (repo: { save(v: unknown): Promise<void> }): Promise<void> => {
  repo.save({ id: 2 });
};

// Call-argument-form async arrow — the Express/NestJS/addEventListener
// callback shape named as the dominant real-world case in the fix wave.
app.post('/users', async (repo: { save(v: unknown): Promise<void> }) => {
  repo.save({ id: 3 });
});

// The receiver as a field and as a compound name — the usual NestJS / TypeORM
// shapes. The receiver regex was anchored at the start, so none fired
// (review 3.6.1, measured on Semgrep 1.182.0).
export class UserService {
  constructor(
    private userRepository: { save(v: unknown): Promise<void> },
    private db: { insert(v: unknown): Promise<void> },
  ) {}

  async create(x: unknown): Promise<void> {
    this.userRepository.save(x);
  }

  async add(x: unknown): Promise<void> {
    this.db.insert(x);
  }
}

export async function compoundName(orderRepo: { save(v: unknown): Promise<void> }): Promise<void> {
  orderRepo.save({ id: 4 });
}
