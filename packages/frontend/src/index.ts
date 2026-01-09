import { Classic } from "@caido/primevue";
import { createPinia } from "pinia";
import PrimeVue from "primevue/config";
import { createApp, defineComponent } from "vue";

import { Configuration } from "./components/Configuration";
import { SDKPlugin } from "./plugins/sdk";
import "./styles/index.css";
import type { FrontendSDK } from "./types";

export const init = (sdk: FrontendSDK) => {
  const app = createApp(defineComponent({}));
  const pinia = createPinia();

  app.use(PrimeVue, {
    unstyled: true,
    pt: Classic,
  });
  app.use(pinia);
  app.use(SDKPlugin, sdk);

  sdk.settings.addToSlot("plugins-section", {
    type: "Custom",
    name: "NTLM",
    definition: { component: Configuration },
  });
};
