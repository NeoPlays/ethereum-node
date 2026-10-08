import { createPinia, setActivePinia } from "pinia";
import { toRaw } from "vue";
import { useServices } from "@/store/services";
import { useNodeManage } from "@/store/nodeManage";
import { useListKeys } from "@/composables/validators";

jest.mock("@/store/ControlService", () => ({
  __esModule: true,
  default: {
    listValidators: jest.fn(),
    listRemoteKeys: jest.fn().mockResolvedValue({ data: [] }),
    readKeys: jest.fn().mockResolvedValue({}),
    writeKeys: jest.fn().mockResolvedValue(),
    getValidatorState: jest.fn().mockResolvedValue([]),
  },
}));
const ControlService = require("@/store/ControlService").default;

// The node page lists keys while the 2s service refresh keeps replacing the services in the store.
// The listing used to put the client object it started with back into the store (by index), so the
// card was swapped for a stale object - with v-for keyed by the object it vanished and came back.
test("keys land on the store entry that is current when the listing returns", async () => {
  setActivePinia(createPinia());
  const serviceStore = useServices();
  useNodeManage().currentNetwork = { network: "hoodi" };
  const vc = {
    id: 0,
    service: "TekuValidatorService",
    category: "validator",
    state: "running",
    config: { serviceID: "teku", network: "hoodi" },
  };
  serviceStore.installedServices = [vc];

  const refreshed = { ...vc, config: { serviceID: "teku", network: "hoodi" } };
  ControlService.listValidators.mockImplementation(async () => {
    // the header refresh swaps in a fresh entry with a new config while the keys are listed
    serviceStore.installedServices = [refreshed];
    return { data: [{ validating_pubkey: "0xa" }, { validating_pubkey: "0xb" }] };
  });

  await useListKeys();

  expect(serviceStore.installedServices).toHaveLength(1);
  expect(toRaw(serviceStore.installedServices[0])).toBe(refreshed); // not swapped for the stale object
  expect(serviceStore.installedServices[0].config.keys.map((k) => k.key)).toEqual(["0xa", "0xb"]);
});
