import { defineStore } from "pinia";
export const useServices = defineStore("services", {
  state: () => {
    return {
      network: "",
      installedServices: [],
      runningServices: [],
      allServices: [
        {
          id: 1,
          name: "Lighthouse",
          service: "LighthouseBeaconService",
          category: "consensus",
          displayCategory: "csc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/lighthouse",
          icon: require("../../public/img/icon/plugin-icons/consensus/LightHouse.png"),
          sIcon: require("../../public/img/icon/plugin-icons/consensus/Lighthouse-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
            {
              title: "Slasher DB Size",
              type: "text",
              changeValue: null,
              icon: "/img/icon/plugin-menu-icons/ram1.png",
              pattern: new RegExp(/(- --slasher-max-db-size=)(\d+)(\n)/),
            }
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 2,
          name: "Lighthouse",
          service: "LighthouseValidatorService",
          category: "validator",
          displayCategory: "vlc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/lighthouse",
          icon: require("../../public/img/icon/plugin-icons/validator/lighthouse-validator.png"),
          sIcon: require("../../public/img/icon/plugin-icons/validator/Lighthouse-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 3,
          name: "Prysm",
          service: "PrysmBeaconService",
          category: "consensus",
          displayCategory: "csc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/prysm",
          icon: require("../../public/img/icon/plugin-icons/consensus/Prysm.png"),
          sIcon: require("../../public/img/icon/plugin-icons/consensus/Prysm-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 4,
          name: "Prysm",
          service: "PrysmValidatorService",
          category: "validator",
          displayCategory: "vlc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/prysm",
          icon: require("../../public/img/icon/plugin-icons/validator/prysm-validator.png"),
          sIcon: require("../../public/img/icon/plugin-icons/validator/Prysm-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 5,
          name: "Nimbus",
          service: "NimbusBeaconService",
          category: "consensus",
          displayCategory: "csc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/nimbus",
          icon: require("../../public/img/icon/plugin-icons/consensus/Nimbus.png"),
          sIcon: require("../../public/img/icon/plugin-icons/consensus/Nimbus-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 6,
          name: "Nimbus",
          service: "NimbusValidatorService",
          category: "validator",
          displayCategory: "vlc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/nimbus",
          icon: require("../../public/img/icon/plugin-icons/validator/nimbus-validator.png"),
          sIcon: require("../../public/img/icon/plugin-icons/validator/Nimbus-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 7,
          name: "Teku",
          service: "TekuBeaconService",
          category: "consensus",
          displayCategory: "csc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/teku",
          icon: require("../../public/img/icon/plugin-icons/consensus/Teku.png"),
          sIcon: require("../../public/img/icon/plugin-icons/consensus/Teku-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
            {
              title: "RAM Usage Limit",
              type: "select",
              value: [2,4,8,16],
              changeValue: null,
              icon: "/img/icon/plugin-menu-icons/ram.png",
              unit: "GB",
              pattern: new RegExp(/(JAVA_OPTS: -Xmx)(\d+)(g)/),
            },
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 8,
          name: "Teku",
          service: "TekuValidatorService",
          category: "validator",
          displayCategory: "vlc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/teku",
          icon: require("../../public/img/icon/plugin-icons/validator/Teku.png"),
          sIcon: require("../../public/img/icon/plugin-icons/validator/Teku-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
            {
              title: "RAM Usage Limit",
              type: "select",
              value: [2,4,8,16],
              changeValue: null,
              icon: "/img/icon/plugin-menu-icons/ram.png",
              unit: "GB",
              pattern: new RegExp(/(JAVA_OPTS: -Xmx)(\d+)(g)/),
            },
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 9,
          name: "Blox-SSV",
          service: "BloxSSVService",
          category: "validator",
          displayCategory: "vlc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/blox-ssv",
          icon: require("../../public/img/icon/plugin-icons/Other/blox-ssv.png"),
          sIcon: require("../../public/img/icon/plugin-icons/Other/Blox-ssv-s.png"),
          hIcon: "/img/icon/service-icons/ssv.png",
          linkUrl: "https://stereum.net",
          headerOption: true,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 10,
          name: "Prometheus",
          service: "PrometheusService",
          category: "service",
          displayPluginMenu: false,
          path: "/prometheus",
          icon: require("../../public/img/icon/plugin-icons/Other/prometheus.png"),
          sIcon: require("../../public/img/icon/plugin-icons/Other/Prometheus-s.png"),
          hIcon: "/img/icon/service-icons/prometheus.png",
          linkUrl: "https://stereum.net",
          headerOption: true,
          expertOptionsModal: false,
          expertOptions: [
          ],
          tunnelLink: true,
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 11,
          name: "Grafana",
          service: "GrafanaService",
          displayPluginMenu: false,
          category: "service",
          path: "/grafana",
          icon: require("../../public/img/icon/plugin-icons/Other/grafana-service.png"),
          sIcon: require("../../public/img/icon/plugin-icons/Other/Grafana-s.png"),
          hIcon: "/img/icon/service-icons/grafana.png",
          linkUrl: "https://stereum.net",
          headerOption: true,
          expertOptionsModal: false,
          expertOptions: [
          ],
          tunnelLink: true,
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 12,
          name: "Geth",
          service: "GethService",
          category: "execution",
          displayCategory: "exc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/geth",
          icon: require("../..//public/img/icon/plugin-icons/execution/Geth.png"),
          sIcon: require("../../public/img/icon/plugin-icons/execution/Geth-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 13,
          name: "Besu",
          service: "BesuService",
          category: "execution",
          displayCategory: "exc",
          displayTooltip: false,
          displayPluginMenu: false,
          path: "/besu",
          icon: require("../..//public/img/icon/plugin-icons/execution/hyperLedger-besu.png"),
          sIcon: require("../../public/img/icon/plugin-icons/execution/HyperLedger-besu-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
        {
          id: 14,
          name: "Nethermind",
          service: "NethermindService",
          category: "execution",
          displayTooltip: false,
          displayPluginMenu: false,
          displayCategory: "exc",
          path: "/nethermind",
          icon: require("../..//public/img/icon/plugin-icons/execution/Nethermind.png"),
          sIcon: require("../../public/img/icon/plugin-icons/execution/Nethermind-s.png"),
          headerOption: false,
          expertOptionsModal: false,
          expertOptions: [
          ],
          drag: true,
          state: "exited",
          config: {
            serviceID: "",
            configVersion: "",
            image: "",
            imageVersion: "",
            ports: [],
            volumes: [],
            network: "",
          },
        },
      ],
      versions: {},
      stereumVersion: {},
      newUpdates: [],
    };
  },
  getters: {},
  actions: {},
});
