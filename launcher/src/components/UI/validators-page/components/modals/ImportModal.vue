<template>
  <ValidatorModal :title="t('validatorsPage.importTitle')" icon="/img/icon/staking-page-icons/validator-import.svg" wide @close="close">
    <!-- 1: files -->
    <template v-if="step === 'files'">
      <label
        class="flex flex-col items-center justify-center gap-1 rounded-lg border-2 border-dashed px-4 py-5 text-xs cursor-pointer transition-colors"
        :class="dragging ? 'border-teal-300 bg-[#224141]' : 'border-[#4b8585] bg-[#0D0D12] hover:border-teal-400'"
        @dragover.prevent="dragging = true"
        @dragleave="dragging = false"
        @drop.prevent="onDrop"
      >
        <img src="/img/icon/staking-page-icons/validator-import.svg" class="w-8 h-8" alt="" />
        <span class="font-semibold">{{ t("validatorsPage.importDrop") }}</span>
        <span class="text-gray-400">{{ t("validatorsPage.importDropHint") }}</span>
        <input type="file" multiple accept=".json,.txt" class="hidden" @change="onPick" />
      </label>

      <div class="flex flex-col gap-1">
        <span class="text-2xs font-semibold uppercase text-[#7fb3b3]">{{ t("validatorsPage.importPassword") }}</span>
        <input
          v-model="sharedPassword"
          type="password"
          :placeholder="t('validatorsPage.importPasswordPlaceholder')"
          class="h-9 rounded-full bg-[#0D0D12] border border-[#4b8585] px-4 text-xs outline-hidden focus:border-teal-400"
        />
      </div>

      <div v-if="keystores.length" class="flex flex-col gap-1 max-h-40 overflow-y-auto">
        <div v-for="(ks, i) in keystores" :key="ks.pubkey" class="flex items-center gap-2 rounded-full bg-[#1d2023] px-3 py-1 text-xs">
          <img src="/img/icon/node-page-icons/validator-key-icon.png" class="w-3.5 h-3.5" alt="" />
          <span class="grow truncate" :title="ks.name">{{ shortPubkey(ks.pubkey) }}</span>
          <span class="text-2xs" :class="passwordOf(ks) ? 'text-gray-400' : 'text-red-400'">
            {{
              ks.password !== null
                ? t("validatorsPage.passwordFile")
                : sharedPassword
                  ? t("validatorsPage.passwordShared")
                  : t("validatorsPage.passwordMissing")
            }}
          </span>
          <button class="text-gray-400 hover:text-white" @click="keystores.splice(i, 1)">✕</button>
        </div>
      </div>
      <div v-if="slashing" class="flex items-center gap-2 rounded-full bg-[#1d2023] px-3 py-1 text-xs">
        <img src="/img/icon/staking-page-icons/validator-state-slashed.png" class="w-3.5 h-3.5" alt="" />
        <span class="grow truncate">{{ t("validatorsPage.slashingFile", { name: slashing.name }) }}</span>
        <button class="text-gray-400 hover:text-white" @click="slashing = null">✕</button>
      </div>
      <p v-for="problem in fileProblems" :key="problem" class="text-2xs text-red-400">{{ problem }}</p>
    </template>

    <!-- 2: check -->
    <template v-else-if="step === 'check'">
      <div v-if="!check" class="flex items-center gap-2 text-sm text-gray-300">
        <img src="/animation/loading/turning-circle.gif" class="w-6 h-6" alt="" />{{ t("validatorsPage.importChecking") }}
      </div>
      <template v-else>
        <p v-if="check.info" class="text-xs text-red-400">{{ check.info }}</p>
        <div class="flex flex-wrap gap-2">
          <span v-for="chip in checkChips" :key="chip.label" class="px-3 py-1 rounded-full text-xs font-semibold border border-[#4b8585]">
            {{ chip.label }}: {{ chip.count }}
          </span>
        </div>
        <p v-if="!check.statesKnown" class="text-xs text-amber-300">{{ t("validatorsPage.importNoStates") }}</p>

        <div
          v-if="check.live?.length"
          class="rounded-lg border border-red-500 bg-red-900/25 px-3 py-2 text-xs text-red-200 flex flex-col gap-2"
        >
          <span class="font-bold">{{ t("validatorsPage.importLive", { count: check.live.length }) }}</span>
          <span class="max-h-20 overflow-y-auto flex flex-col text-2xs">
            <span v-for="key in check.live" :key="key" class="break-all">{{ key }}</span>
          </span>
          <label class="flex items-start gap-2 cursor-pointer">
            <input v-model="liveAccepted" type="checkbox" class="mt-0.5" />{{ t("validatorsPage.importLiveAccept") }}
          </label>
        </div>

        <div
          class="rounded-lg border px-3 py-2 text-xs flex flex-col gap-1"
          :class="slashingCheck?.ok === false ? 'border-red-500 text-red-200' : 'border-[#4b8585]'"
        >
          <template v-if="slashingCheck">
            <span v-if="slashingCheck.ok">{{ t("validatorsPage.slashingOk") }}</span>
            <span v-else>{{ t("validatorsPage.slashingRejected", { reasons: slashingCheck.errors.join(", ") }) }}</span>
          </template>
          <span v-else>{{ t("validatorsPage.slashingNone") }}</span>
          <label v-if="needsNeverSigned" class="flex items-start gap-2 cursor-pointer text-amber-200">
            <input v-model="neverSigned" type="checkbox" class="mt-0.5" />{{
              t("validatorsPage.slashingNeverSigned", { count: uncoveredOnChain.length })
            }}
          </label>
        </div>

        <p v-if="check.doppelganger" class="text-xs text-sky-300">{{ t("validatorsPage.importDoppelganger") }}</p>
      </template>
    </template>

    <!-- 3: importing -->
    <div v-else-if="step === 'importing'" class="flex items-center gap-2 text-sm text-gray-300">
      <img src="/animation/loading/turning-circle.gif" class="w-6 h-6" alt="" />{{
        t("validatorsPage.importing", { count: keystores.length })
      }}
    </div>

    <!-- 4: done -->
    <ImportResult v-else :results="result.results ?? []" :info="result.info ?? null" :doppelganger="!!check?.doppelganger" />

    <template #footer>
      <template v-if="step === 'files'">
        <ActionButton :label="t('validatorsPage.cancel')" @click="close" />
        <ActionButton :label="t('validatorsPage.next')" primary :disabled="!filesReady" @click="runCheck" />
      </template>
      <template v-else-if="step === 'check'">
        <ActionButton :label="t('validatorsPage.back')" @click="step = 'files'" />
        <ActionButton
          :label="t('validatorsPage.importConfirm', { count: keystores.length })"
          primary
          :disabled="!importAllowed"
          @click="runImport"
        />
      </template>
      <ActionButton v-else-if="step === 'done'" :label="t('validatorsPage.close')" primary @click="close" />
    </template>
  </ValidatorModal>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import ValidatorModal from "../ValidatorModal.vue";
import ActionButton from "../ActionButton.vue";
import ImportResult from "./ImportResult.vue";
import ControlService from "@/store/ControlService";
import { useValidatorsStore } from "@/store/validators";
import { parseKeystore, checkSlashingProtection } from "@/share/keystores";
import { shortPubkey } from "@/share/validatorStatus";
import i18n from "@/includes/i18n";

const props = defineProps({ files: { type: Array, default: () => [] } });
const emit = defineEmits(["close"]);

const t = i18n.global.t;
const validatorsStore = useValidatorsStore();
const holderId = validatorsStore.selectedHolderId;

const step = ref("files");
const dragging = ref(false);
// { name, pubkey, text, password: text of a matching .txt or null }
const keystores = ref([]);
const passwordFiles = ref({});
const slashing = ref(null);
const fileProblems = ref([]);
const sharedPassword = ref("");

const baseName = (name) => name.replace(/\.(json|txt)$/i, "");
const passwordOf = (ks) => ks.password ?? passwordFiles.value[baseName(ks.name)] ?? (sharedPassword.value || null);

// keystores, their password files and a slashing protection file can be dropped together
const addFiles = async (files) => {
  for (const file of files) {
    const text = await file.text();
    if (/\.txt$/i.test(file.name)) {
      passwordFiles.value[baseName(file.name)] = text.replace(/\r?\n$/, "");
      continue;
    }
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      /* reported below */
    }
    if (json?.metadata && Array.isArray(json?.data)) {
      slashing.value = { name: file.name, text };
      continue;
    }
    const parsed = parseKeystore(text);
    if (parsed.error) fileProblems.value.push(`${file.name}: ${parsed.error}`);
    else if (!keystores.value.some((k) => k.pubkey === parsed.pubkey))
      keystores.value.push({ name: file.name, pubkey: parsed.pubkey, text, password: null });
  }
  keystores.value.forEach((ks) => (ks.password = passwordFiles.value[baseName(ks.name)] ?? null));
};
const onDrop = (event) => {
  dragging.value = false;
  addFiles([...event.dataTransfer.files]);
};
const onPick = (event) => addFiles([...event.target.files]);

const filesReady = computed(() => keystores.value.length > 0 && keystores.value.every((ks) => passwordOf(ks)));

// check
const check = ref(null);
const liveAccepted = ref(false);
const neverSigned = ref(false);
const slashingCheck = computed(() =>
  slashing.value && check.value?.genesisRoot
    ? checkSlashingProtection(slashing.value.text, { genesisRoot: check.value.genesisRoot, pubkeys: keystores.value.map((k) => k.pubkey) })
    : null
);
// keys on chain that the slashing protection does not cover may have signed before; the user has to vouch for them
const uncoveredOnChain = computed(() => {
  const covered = slashingCheck.value?.ok
    ? new Set(keystores.value.map((k) => k.pubkey).filter((k) => !slashingCheck.value.missing.includes(k)))
    : new Set();
  return keystores.value.map((k) => k.pubkey).filter((k) => check.value?.onChain?.[k] && !covered.has(k));
});
const needsNeverSigned = computed(() => uncoveredOnChain.value.length > 0);
const importAllowed = computed(
  () =>
    check.value &&
    !check.value.info &&
    slashingCheck.value?.ok !== false &&
    (!check.value.live?.length || liveAccepted.value) &&
    (!needsNeverSigned.value || neverSigned.value)
);
const checkChips = computed(() => {
  const onChain = Object.values(check.value?.onChain ?? {});
  return [
    { label: t("validatorsPage.importKeys"), count: keystores.value.length },
    { label: t("validatorsPage.importAlready"), count: check.value?.alreadyImported?.length ?? 0 },
    { label: t("validatorsPage.status.active"), count: onChain.filter((s) => String(s.status).startsWith("active")).length },
    { label: t("validatorsPage.status.unknown"), count: keystores.value.length - onChain.length },
  ].filter((chip, i) => i === 0 || chip.count);
});
const runCheck = async () => {
  step.value = "check";
  check.value = null;
  liveAccepted.value = false;
  neverSigned.value = false;
  check.value = await ControlService.prepareKeyImport(
    holderId,
    keystores.value.map((k) => k.pubkey)
  );
};

// import
const result = ref(null);
const runImport = async () => {
  if (!importAllowed.value) return;
  step.value = "importing";
  result.value = await validatorsStore.importKeys(
    holderId,
    keystores.value.map((k) => k.text),
    keystores.value.map((k) => passwordOf(k)),
    slashingCheck.value?.ok ? slashing.value.text : null
  );
  step.value = "done";
};

const close = () => {
  if (step.value === "importing") return;
  emit("close");
};

onMounted(() => props.files.length && addFiles(props.files));
</script>
