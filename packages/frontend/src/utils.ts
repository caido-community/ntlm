import type { RuleConfig } from "@/types";

// eslint-disable-next-line @typescript-eslint/no-restricted-types
type UndefinedOrNull = null | undefined;

type Maybe<T> = T | UndefinedOrNull;

export const emptyRule = (): RuleConfig => ({
  id: crypto.randomUUID(),
  name: "",
  enabled: true,
  credentials: {
    username: "",
    password: "",
  },
  allowList: [],
  denyList: [],
});

export const isAbsent = <T>(value: Maybe<T>): value is UndefinedOrNull => {
  return value === undefined || value === null;
};
