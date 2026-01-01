export type UserRole = "normal" | "admin";

export type User = {
  username: string;
  password: string;
  role: UserRole;
};

export const users: User[] = [
  { username: "user", password: "password", role: "normal" },
  { username: "admin", password: "admin123", role: "admin" },
];

export function findUser(username: string): User | undefined {
  return users.find((u) => u.username.toLowerCase() === username.toLowerCase());
}
