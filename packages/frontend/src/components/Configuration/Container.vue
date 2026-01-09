<script setup lang="ts">
import Button from "primevue/button";
import { onMounted, ref } from "vue";

import RuleForm from "./RuleForm.vue";
import RuleTable from "./RuleTable.vue";

import { useConfigStore } from "@/stores/config";
import { useUpstreamStore } from "@/stores/upstream";
import type { RuleConfig } from "@/types";

const store = useConfigStore();
const upstreamStore = useUpstreamStore();

const showForm = ref(false);
const editingRule = ref<RuleConfig | undefined>();
const editingIndex = ref<number | undefined>();

onMounted(() => {
  store.loadConfig();
});

const handleAddRule = () => {
  editingRule.value = undefined;
  editingIndex.value = undefined;
  showForm.value = true;
};

const handleEditRule = (rule: RuleConfig, index: number) => {
  editingRule.value = rule;
  editingIndex.value = index;
  showForm.value = true;
};

const handleSaveRule = async (rule: RuleConfig, index?: number) => {
  if (index !== undefined) {
    store.updateRule(index, rule);
  } else {
    store.addRule(rule);
  }
  await store.saveConfig();
};

const handleAddAsUpstream = (rule: RuleConfig) => {
  upstreamStore.addRuleAsUpstream(rule);
};
</script>

<template>
  <div class="flex flex-col gap-4">
    <div class="flex justify-between items-center">
      <h3 class="text-lg font-semibold">Rules</h3>
      <Button label="Add Rule" @click="handleAddRule" />
    </div>

    <div v-if="store.config.rules.length === 0" class="text-gray-500">
      No rules configured. Click "Add Rule" to get started.
    </div>

    <RuleTable
      v-else
      @edit="handleEditRule"
      @add-as-upstream="handleAddAsUpstream"
    />

    <RuleForm
      v-model="showForm"
      :index="editingIndex"
      :rule="editingRule"
      @save="handleSaveRule"
    />
  </div>
</template>
