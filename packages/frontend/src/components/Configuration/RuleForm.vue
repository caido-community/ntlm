<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import InputText from "primevue/inputtext";
import ToggleSwitch from "primevue/toggleswitch";
import { computed, ref, watch } from "vue";

import type { RuleConfig } from "@/types";
import { emptyRule } from "@/utils";

const props = defineProps<{
  modelValue: boolean;
  rule?: RuleConfig;
  index?: number;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
  save: [rule: RuleConfig, index?: number];
}>();

const isOpen = computed({
  get: () => props.modelValue,
  set: (value) => emit("update:modelValue", value),
});

const formData = ref<RuleConfig>({
  ...emptyRule(),
});

const allowListText = ref("");
const denyListText = ref("");

const resetForm = () => {
  formData.value = emptyRule();
  allowListText.value = "";
  denyListText.value = "";
};

watch(
  () => props.rule,
  (rule) => {
    if (rule !== undefined) {
      formData.value = {
        id: rule.id,
        name: rule.name,
        enabled: rule.enabled,
        credentials: {
          username: rule.credentials.username,
          password: rule.credentials.password,
        },
        allowList: [...rule.allowList],
        denyList: [...rule.denyList],
      };
      allowListText.value = rule.allowList.join("\n");
      denyListText.value = rule.denyList.join("\n");
    } else {
      resetForm();
    }
  },
  { immediate: true },
);

watch(
  () => isOpen.value,
  (open) => {
    if (!open) {
      resetForm();
    }
  },
);

const handleSave = () => {
  const rule: RuleConfig = {
    ...formData.value,
    allowList: allowListText.value
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== ""),
    denyList: denyListText.value
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== ""),
  };
  emit("save", rule, props.index);
  isOpen.value = false;
};

const handleCancel = () => {
  isOpen.value = false;
};
</script>

<template>
  <Dialog
    v-model:visible="isOpen"
    :header="rule !== undefined ? 'Edit Rule' : 'Add Rule'"
    modal
    class="w-full max-w-2xl"
  >
    <div class="space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1">Name</label>
        <InputText
          v-model="formData.name"
          placeholder="Rule name"
          class="w-full"
        />
      </div>

      <div>
        <label class="block text-sm font-medium mb-1">Enabled</label>
        <ToggleSwitch v-model="formData.enabled" />
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="block text-sm font-medium mb-1">Username</label>
          <InputText
            v-model="formData.credentials.username"
            placeholder="Username"
            class="w-full"
          />
        </div>
        <div>
          <label class="block text-sm font-medium mb-1">Password</label>
          <InputText
            v-model="formData.credentials.password"
            type="password"
            placeholder="Password"
            class="w-full"
          />
        </div>
      </div>

      <div>
        <label class="block text-sm font-medium mb-1"
          >Allow List (glob patterns, one per line)</label
        >
        <textarea
          v-model="allowListText"
          class="w-full p-2 border border-surface-600 rounded bg-surface-800 text-surface-100"
          placeholder="*.example.com&#10;*.test.com"
          rows="3"
        />
      </div>

      <div>
        <label class="block text-sm font-medium mb-1"
          >Deny List (glob patterns, one per line)</label
        >
        <textarea
          v-model="denyListText"
          class="w-full p-2 border border-surface-600 rounded bg-surface-800 text-surface-100"
          placeholder="*.blocked.com&#10;*.forbidden.com"
          rows="3"
        />
      </div>
    </div>

    <template #footer>
      <div class="flex justify-end gap-2">
        <Button label="Cancel" severity="secondary" @click="handleCancel" />
        <Button label="Save" @click="handleSave" />
      </div>
    </template>
  </Dialog>
</template>
