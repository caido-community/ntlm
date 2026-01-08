<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import ToggleSwitch from "primevue/toggleswitch";

import { useConfigStore } from "@/stores/config";
import type { RuleConfig } from "@/types";

defineProps<{
  onEdit: (rule: RuleConfig, index: number) => void;
}>();

const store = useConfigStore();

const handleRowReorder = async (event: {
  value: RuleConfig[];
  dragIndex: number;
  dropIndex: number;
}) => {
  await store.reorderRules(event);
};

const handleToggleRule = async (index: number) => {
  await store.toggleRule(index);
};

const handleRemoveRule = async (index: number) => {
  await store.removeRule(index);
};
</script>

<template>
  <DataTable
    :value="store.config.rules"
    row-reorder
    striped-rows
    class="w-full"
    @row-reorder="handleRowReorder"
  >
    <Column row-reorder style="width: 3rem" />
    <Column header="Enabled" style="width: 6rem">
      <template #body="{ data, index }">
        <ToggleSwitch
          :model-value="data.enabled"
          @update:model-value="handleToggleRule(index)"
        />
      </template>
    </Column>
    <Column field="name" header="Name" />
    <Column header="Included Domains">
      <template #body="{ data }">
        <div class="text-sm">
          {{ data.allowList.length > 0 ? data.allowList.join(", ") : "All" }}
        </div>
      </template>
    </Column>
    <Column header="Excluded Domains">
      <template #body="{ data }">
        <div class="text-sm">
          {{ data.denyList.length > 0 ? data.denyList.join(", ") : "None" }}
        </div>
      </template>
    </Column>
    <Column header="Actions">
      <template #body="{ data, index }">
        <div class="flex gap-2">
          <Button
            icon="fas fa-edit"
            severity="secondary"
            size="small"
            @click="onEdit(data, index)"
          />
          <Button
            icon="fas fa-trash"
            severity="danger"
            size="small"
            @click="handleRemoveRule(index)"
          />
        </div>
      </template>
    </Column>
  </DataTable>
</template>
