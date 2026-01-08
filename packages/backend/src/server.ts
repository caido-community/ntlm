import { minimatch } from "minimatch";

import type { RuleConfig } from "./config.js";

export class Rule {
  constructor(private config: RuleConfig) {}

  matches(domain: string): boolean {
    if (this.config.denyList.length > 0) {
      for (const pattern of this.config.denyList) {
        if (minimatch(domain, pattern)) {
          return false;
        }
      }
    }

    if (this.config.allowList.length > 0) {
      for (const pattern of this.config.allowList) {
        if (minimatch(domain, pattern)) {
          return true;
        }
      }
      return false;
    }

    return true;
  }

  getCredentials() {
    return this.config.credentials;
  }

  getName() {
    return this.config.name;
  }
}
