/** Where the views are reached from besides the navigator: resource menus, the navigator's menu, the command palette. */

import { getCommandInjectableBunch } from "@k8slens/command-palette-contracts";
import { DropDownMenuItemRow } from "@k8slens/drop-down-menu-items";
import { LayersIcon, NetworkIcon, OpenInBrowserIcon, PeopleIcon, PolicyIcon } from "@k8slens/icon";
import { getKubeResourceMenuItemInjectableBunch, type KubeResourceMenuTarget, kubeResourceMenuOrderNumbers } from "@k8slens/kube-resource-menu-contracts";
import { activeTabClusterIdInjectionToken, activeTabClusterIdReactiveInjectionToken } from "@k8slens/main-view-contracts";
import { getNavigatorItemMenuItemInjectableBunch, type NavigatorItemOfKind, navigatorItemDropDownMenuOrderNumbers } from "@k8slens/navigator-contracts";
import { useInject } from "@k8slens/use-inject";
import { computed } from "mobx";
import { copyToLabInjectable, inspectServiceAccountInjectable, simulateFromPodInjectable, simulatePoliciesForResourceInjectable } from "./actions.injectable";
import { openGovernanceViewInjectable } from "./navigation.injectable";
import { governanceViewItemKind } from "./navigator.injectable";
import { governanceViews } from "./views";

const InspectServiceAccount = ({ data }: { data: KubeResourceMenuTarget }) => {
  const inspect = useInject(inspectServiceAccountInjectable)();

  return (
    <DropDownMenuItemRow Icon={PeopleIcon} $onClick={() => void inspect(data.clusterId, data.namespace ?? "default", data.name)}>
      Inspect permissions
    </DropDownMenuItemRow>
  );
};

export const inspectServiceAccountMenuItem = getKubeResourceMenuItemInjectableBunch({
  id: "real-governance-inspect-service-account-menu-item",
  appliesToKind: "ServiceAccount",
  orderNumber: kubeResourceMenuOrderNumbers.sectionEnd + 100,
  Component: InspectServiceAccount,
});

const SimulateFromPod = ({ data }: { data: KubeResourceMenuTarget }) => {
  const simulate = useInject(simulateFromPodInjectable)();

  return (
    <DropDownMenuItemRow Icon={NetworkIcon} $onClick={() => void simulate(data.clusterId, data.namespace ?? "default", data.name)}>
      Check network reachability
    </DropDownMenuItemRow>
  );
};

export const simulateFromPodMenuItem = getKubeResourceMenuItemInjectableBunch({
  id: "real-governance-simulate-from-pod-menu-item",
  appliesToKind: "Pod",
  orderNumber: kubeResourceMenuOrderNumbers.sectionEnd + 110,
  Component: SimulateFromPod,
});

const SimulatePolicies = ({ data }: { data: KubeResourceMenuTarget }) => {
  const simulate = useInject(simulatePoliciesForResourceInjectable)();

  return (
    <DropDownMenuItemRow Icon={PolicyIcon} $onClick={() => void simulate(data)}>
      Admission policies that apply
    </DropDownMenuItemRow>
  );
};

export const simulatePoliciesMenuItem = getKubeResourceMenuItemInjectableBunch({
  id: "real-governance-simulate-policies-menu-item",
  orderNumber: kubeResourceMenuOrderNumbers.sectionEnd + 120,
  Component: SimulatePolicies,
});

const CopyToLab = ({ data }: { data: KubeResourceMenuTarget }) => {
  const copy = useInject(copyToLabInjectable)();

  return (
    <DropDownMenuItemRow Icon={LayersIcon} $onClick={() => void copy(data)}>
      Copy into the policy lab
    </DropDownMenuItemRow>
  );
};

export const copyToLabMenuItem = getKubeResourceMenuItemInjectableBunch({
  id: "real-governance-copy-to-lab-menu-item",
  orderNumber: kubeResourceMenuOrderNumbers.sectionEnd + 130,
  Component: CopyToLab,
});

const OpenView = ({ data }: { data: NavigatorItemOfKind<typeof governanceViewItemKind> }) => {
  const openView = useInject(openGovernanceViewInjectable)();
  const [clusterId, , view] = data.ids;

  return (
    <DropDownMenuItemRow Icon={OpenInBrowserIcon} $onClick={() => void openView(clusterId, view as (typeof governanceViews)[number]["view"])}>
      Open
    </DropDownMenuItemRow>
  );
};

export const openViewNavigatorMenuItem = getNavigatorItemMenuItemInjectableBunch({
  id: "real-governance-open-view-menu-item",
  forItemsOfKind: governanceViewItemKind,
  orderNumber: navigatorItemDropDownMenuOrderNumbers.item,
  Component: OpenView,
});

const commandFor = (entry: (typeof governanceViews)[number]) =>
  getCommandInjectableBunch({
    id: `real-governance.open-${entry.view}`,
    title: `Governance: ${entry.title} of this cluster`,
    isActive: {
      consumptions: [activeTabClusterIdReactiveInjectionToken],
      instantiate: (di) => {
        const activeClusterId = di.inject(activeTabClusterIdReactiveInjectionToken)();

        return () => computed(() => activeClusterId.get() !== undefined);
      },
    },
    action: {
      consumptions: [activeTabClusterIdInjectionToken],
      instantiate: (di) => {
        const activeClusterId = di.inject(activeTabClusterIdInjectionToken)();
        const openView = di.inject(openGovernanceViewInjectable)();

        return () => async () => {
          const clusterId = await activeClusterId();

          if (clusterId) await openView(clusterId, entry.view);
        };
      },
    },
  });

export const openRbacCommand = commandFor(governanceViews[0]!);
export const openPoliciesCommand = commandFor(governanceViews[1]!);
export const openNetworkCommand = commandFor(governanceViews[2]!);
export const openLabCommand = commandFor(governanceViews[3]!);
