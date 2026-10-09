<template>
  <div class="flex items-center gap-2 rounded-lg bg-[#0D0D12] border border-[#ffffff16] px-3 py-2">
    <img src="/img/icon/node-page-icons/validator-key-icon.png" class="w-4 h-4 shrink-0" alt="" />
    <div class="flex flex-col min-w-0">
      <span v-if="alias" class="text-xs font-bold text-[#7fb3b3]">{{ alias }}</span>
      <span class="text-2xs text-gray-300 break-all select-text">{{ pubkey }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from "vue";
import { useValidatorsStore } from "@/store/validators";

// The key an action applies to, shown at the top of every modal
const props = defineProps({ pubkey: { type: String, required: true } });
const validatorsStore = useValidatorsStore();
const alias = computed(() => validatorsStore.aliases[props.pubkey]?.keyName);
</script>
