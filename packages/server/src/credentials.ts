import { logger } from "./logger.js";

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
  logger.debug({ username, totalUsers: users.length }, "Looking up user");
  const user = users.find(
    (u) => u.username.toLowerCase() === username.toLowerCase(),
  );
  if (user) {
    logger.debug({ username: user.username, role: user.role }, "User found");
  } else {
    logger.debug({ username }, "User not found");
  }
  return user;
}
