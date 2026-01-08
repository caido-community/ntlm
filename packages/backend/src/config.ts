export type CredentialSet = {
  username: string;
  password: string;
};

export type RuleConfig = {
  id: string;
  name: string;
  enabled: boolean;
  credentials: CredentialSet;
  allowList: string[];
  denyList: string[];
};

export type NtlmConfig = {
  rules: RuleConfig[];
};
