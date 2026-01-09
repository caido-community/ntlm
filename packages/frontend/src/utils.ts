import type { RuleConfig } from "@/types";

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
