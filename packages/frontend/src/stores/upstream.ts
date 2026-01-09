import { defineStore } from "pinia";
import { ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import type { RuleConfig } from "@/types";
import { isAbsent } from "@/utils";

export const useUpstreamStore = defineStore("upstream", () => {
  const sdk = useSDK();
  const loading = ref(false);

  const addRuleAsUpstream = async (rule: RuleConfig) => {
    loading.value = true;
    try {
      const pluginId = await sdk.backend.getPluginId();
      const result = await sdk.graphql.createUpstreamPlugin({
        input: {
          allowlist: rule.allowList,
          denylist: rule.denyList,
          enabled: rule.enabled,
          pluginId,
        },
      });

      if (isAbsent(result)) {
        throw new Error("Failed to add rule as upstream plugin");
      }

      sdk.window.showToast("Rule added as upstream plugin", {
        variant: "success",
      });
    } catch (error) {
      sdk.window.showToast(`Failed to add rule as upstream plugin`, {
        variant: "error",
      });
    } finally {
      loading.value = false;
    }
  };

  return {
    loading,
    addRuleAsUpstream,
  };
});
