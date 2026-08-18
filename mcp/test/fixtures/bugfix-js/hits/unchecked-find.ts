interface User {
  id: string;
  name: string;
}

export function nameOf(users: User[], id: string): string {
  return users.find((u) => u.id === id).name;
}
