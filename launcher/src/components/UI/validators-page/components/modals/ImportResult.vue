<template>
  <p v-if="info" class="text-xs text-red-400">{{ info }}</p>
  <div class="flex flex-wrap gap-2">
    <span
      v-for="(count, status) in counts"
      :key="status"
      class="px-3 py-1 rounded-full text-xs font-semibold border"
      :class="status === 'error' ? 'border-red-500 text-red-300' : 'border-[#4b8585]'"
    >
      {{ t(`validatorsPage.importStatus.${status}`, status) }}: {{ count }}
    </span>
  </div>
  <div v-if="failed.length" class="max-h-32 overflow-y-auto flex flex-col gap-1">
    <span v-for="f in failed" :key="f.pubkey" class="text-2xs text-red-300 break-all">{{ shortPubkey(f.pubkey) }}: {{ f.message }}</span>
  </div>
  <p v-if="doppelganger && counts.imported" class="text-xs text-sky-300">{{ t("validatorsPage.importDoppelganger") }}</p>
</template>

<script setup>
import { computed } from "vue";
import { shortPubkey } from "@/share/validatorStatus";
import i18n from "@/includes/i18n";

// Outcome of a keystore or remote key import, shared so both modals report it the same way
const props = defineProps({
  results: { type: Array, default: () => [] },
  info: { type: String, default: null },
  doppelganger: { type: Boolean, default: false },
});

const t = i18n.global.t;
const counts = computed(() => {
  const result = {};
  for (const r of props.results) result[r.status] = (result[r.status] ?? 0) + 1;
  return result;
});
const failed = computed(() => props.results.filter((r) => r.status === "error"));
</script>
