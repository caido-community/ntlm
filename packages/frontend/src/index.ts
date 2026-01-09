import { Classic } from "@caido/primevue";
import { createPinia } from "pinia";
import PrimeVue from "primevue/config";
import { createApp, defineComponent } from "vue";

import { Configuration } from "./components/Configuration";
import { SDKPlugin } from "./plugins/sdk";
import "./styles/index.css";
import type { FrontendSDK } from "./types";

// This is the entry point for the frontend plugin
export const init = (sdk: FrontendSDK) => {
  const app = createApp(defineComponent({}));
  const pinia = createPinia();

  // Load the PrimeVue component library
  app.use(PrimeVue, {
    unstyled: true,
    pt: Classic,
  });

  // Load Pinia
  app.use(pinia);

  // Provide the FrontendSDK
  app.use(SDKPlugin, sdk);

  // @ts-expect-error settings is not yet typed in the frontend SDK
  sdk.settings.addToSlot("plugins-section", {
    type: "Custom",
    name: "NTLM",
    definition: { component: Configuration },
  });
};
