import { defineStore } from "pinia";
import { ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import type { NtlmConfig, RuleConfig } from "@/types";

export const useConfigStore = defineStore("config", () => {
  const sdk = useSDK();
  const config = ref<NtlmConfig>({ rules: [] });
  const loading = ref(false);

  const loadConfig = async () => {
    loading.value = true;
    try {
      const result = await sdk.backend.getConfig();
      config.value = result;
    } catch (error) {
      sdk.window.showToast("Failed to load configuration", {
        variant: "error",
      });
    } finally {
      loading.value = false;
    }
  };

  const saveConfig = async () => {
    loading.value = true;
    try {
      await sdk.backend.saveConfig(config.value);
      sdk.window.showToast("Configuration saved", { variant: "success" });
    } catch (error) {
      sdk.window.showToast("Failed to save configuration", {
        variant: "error",
      });
    } finally {
      loading.value = false;
    }
  };

  const addRule = (rule: RuleConfig) => {
    config.value.rules.push(rule);
  };

  const updateRule = (index: number, rule: RuleConfig) => {
    const existing = config.value.rules[index];
    if (existing !== undefined) {
      config.value.rules[index] = rule;
    }
  };

  const toggleRule = async (index: number) => {
    const rule = config.value.rules[index];
    if (rule !== undefined) {
      rule.enabled = rule.enabled !== true;
      await saveConfig();
    }
  };

  const reorderRules = async (event: {
    value: RuleConfig[];
    dragIndex: number;
    dropIndex: number;
  }) => {
    config.value.rules = event.value;
    await saveConfig();
  };

  const removeRule = async (index: number) => {
    config.value.rules.splice(index, 1);
    await saveConfig();
  };

  return {
    config,
    loading,
    loadConfig,
    saveConfig,
    addRule,
    updateRule,
    removeRule,
    toggleRule,
    reorderRules,
  };
});
