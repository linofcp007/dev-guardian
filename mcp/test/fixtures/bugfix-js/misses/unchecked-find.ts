interface User {
  id: string;
  name: string;
}

export function nameOfOptional(users: User[], id: string): string | undefined {
  return users.find((u) => u.id === id)?.name;
}

export function nameOfGuarded(users: User[], id: string): string {
  const user = users.find((u) => u.id === id);
  if (user) {
    return user.name;
  }
  return 'unknown';
}
