<template>
  <ValidatorModal :title="meta.title" :icon="meta.icon" @close="$emit('close')">
    <KeyLabel v-if="single" :pubkey="pubkeys[0]" />
    <div v-else class="flex items-center gap-2 rounded-lg bg-[#0D0D12] border border-[#ffffff16] px-3 py-2 text-xs">
      <img src="/img/icon/node-page-icons/validator-key-icon.png" class="w-4 h-4" alt="" />
      {{ t("validatorsPage.appliesTo", { count: pubkeys.length }) }}
    </div>

    <div v-if="single" class="flex flex-col gap-1">
      <span class="text-2xs font-semibold uppercase text-[#7fb3b3]">{{ t("validatorsPage.current") }}</span>
      <span v-if="current?.loading" class="flex items-center gap-2 text-xs text-gray-400">
        <img src="/animation/loading/turning-circle.gif" class="w-4 h-4" alt="" />{{ t("validatorsPage.loading") }}
      </span>
      <span v-else-if="current?.error" class="text-xs text-amber-300 break-all">{{ current.error }}</span>
      <span v-else class="text-sm font-semibold break-all select-text">{{ currentValue || "-" }}</span>
    </div>

    <div class="flex flex-col gap-1">
      <div class="flex items-center justify-between">
        <span class="text-2xs font-semibold uppercase text-[#7fb3b3]">{{ meta.newLabel }}</span>
        <span v-if="setting === 'graffiti'" class="text-2xs" :class="bytes > 32 ? 'text-red-400' : 'text-gray-500'"
          >{{ bytes }} / 32 bytes</span
        >
      </div>
      <input
        ref="input"
        v-model="draft"
        :placeholder="meta.placeholder"
        class="h-9 rounded-full bg-[#0D0D12] border px-4 text-xs outline-hidden"
        :class="draft && !valid ? 'border-red-500' : 'border-[#4b8585] focus:border-teal-400'"
        @keydown.enter="save"
      />
    </div>

    <p v-if="csmUnconfirmed" class="text-xs text-amber-300">{{ t("validatorsPage.csm.feeRecipientUnconfirmed") }}</p>
    <p v-else-if="csmKeys.length" class="text-xs text-amber-300">
      {{
        targets.length
          ? t("validatorsPage.csm.feeRecipientSkipped", { count: csmKeys.length })
          : t("validatorsPage.csm.feeRecipientBlocked")
      }}
    </p>

    <div v-if="result" class="text-xs" :class="result.failed?.length || result.info ? 'text-amber-300' : 'text-green-400'">
      <template v-if="result.info">{{ result.info }}</template>
      <template v-else>
        {{ t("validatorsPage.appliedCount", { ok: result.ok.length, total: targets.length }) }}
        <span v-if="result.failed.length">{{ t("validatorsPage.failedCount", { count: result.failed.length }) }}</span>
      </template>
    </div>

    <template #footer>
      <ActionButton :label="t('validatorsPage.resetDefault')" :disabled="busy || !targets.length" @click="apply(null)" />
      <ActionButton :label="t('validatorsPage.save')" primary :disabled="!valid || busy || !targets.length" @click="save" />
    </template>
  </ValidatorModal>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from "vue";
import ValidatorModal from "../ValidatorModal.vue";
import ActionButton from "../ActionButton.vue";
import KeyLabel from "./KeyLabel.vue";
import { useValidatorsStore } from "@/store/validators";
import { useServices } from "@/store/services";
import { FEE_RECIPIENT } from "@/share/validatorStatus";
import i18n from "@/includes/i18n";

const props = defineProps({
  setting: { type: String, required: true }, // "graffiti" | "feerecipient"
  pubkeys: { type: Array, required: true },
});
defineEmits(["close"]);

const t = i18n.global.t;
const validatorsStore = useValidatorsStore();
const holderId = validatorsStore.selectedHolderId;
const single = computed(() => props.pubkeys.length === 1);
// Lido CSM requires its execution layer rewards vault as fee recipient and penalises any other, so those keys are left out
const csmKeys = computed(() => (props.setting === "feerecipient" ? props.pubkeys.filter((p) => p in validatorsStore.csm.keys) : []));
// until a CSM lookup of this server succeeded, any key may be a CSM key
const serviceStore = useServices();
const csmUnconfirmed = computed(
  () =>
    props.setting === "feerecipient" &&
    !validatorsStore.csm.loadedAt &&
    (validatorsStore.csm.installed || serviceStore.installedServices.some((s) => s.service === "LCOMService"))
);
const targets = computed(() => (csmUnconfirmed.value ? [] : props.pubkeys.filter((p) => !csmKeys.value.includes(p))));

const meta = computed(() =>
  props.setting === "graffiti"
    ? {
        title: t("validatorsPage.graffiti"),
        icon: "/img/icon/staking-page-icons/option-graffiti.png",
        newLabel: t("validatorsPage.graffitiNew"),
        placeholder: t("validatorsPage.graffitiPlaceholder"),
      }
    : {
        title: t("validatorsPage.feeRecipient"),
        icon: "/img/icon/staking-page-icons/option-fee-recepient.png",
        newLabel: t("validatorsPage.feeRecipientNew"),
        placeholder: t("validatorsPage.feeRecipientPlaceholder"),
      }
);

const current = computed(() =>
  props.setting === "graffiti" ? validatorsStore.graffitis[props.pubkeys[0]] : validatorsStore.feeRecipients[props.pubkeys[0]]
);
const currentValue = computed(() => (props.setting === "graffiti" ? current.value?.graffiti : current.value?.address));

const draft = ref("");
const input = ref(null);
const busy = ref(false);
const result = ref(null);
const bytes = computed(() => new TextEncoder().encode(draft.value).length);
// graffiti: up to 32 bytes on chain, no line breaks; fee recipient: an execution address
const valid = computed(() =>
  props.setting === "graffiti"
    ? draft.value.length > 0 && bytes.value <= 32 && ![...draft.value].some((c) => c.charCodeAt(0) < 32)
    : FEE_RECIPIENT.test(draft.value.trim())
);

const apply = async (value) => {
  if (!targets.value.length) return;
  busy.value = true;
  result.value = null;
  try {
    result.value = await validatorsStore.applyKeySetting(holderId, targets.value, props.setting, value);
    if (result.value.code === 0 && !result.value.failed.length) draft.value = "";
  } finally {
    busy.value = false;
  }
};
const save = () => valid.value && !busy.value && apply(props.setting === "graffiti" ? draft.value : draft.value.trim());

onMounted(async () => {
  if (single.value) {
    if (props.setting === "graffiti") validatorsStore.loadGraffiti(holderId, props.pubkeys[0]);
    else validatorsStore.loadFeeRecipient(holderId, props.pubkeys[0]);
  }
  await nextTick();
  input.value?.focus();
});
</script>
