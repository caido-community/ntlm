<script setup lang="ts">
import Card from "primevue/card";

import { ConfigurationContainer } from "@/components/Configuration";
</script>

<template>
  <div class="h-full p-4 overflow-auto">
    <Card class="w-full max-w-4xl mx-auto">
      <template #title>NTLM Configuration</template>
      <template #content>
        <ConfigurationContainer />
      </template>
    </Card>
  </div>
</template>
