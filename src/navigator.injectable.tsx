import { clusterNavigatorItemKind } from "@k8slens/cluster-contracts";
import { SecurityIcon } from "@k8slens/icon";
import {
  NavigatorBranchIndicator,
  NavigatorDrillDownButton,
  NavigatorItemActions,
  NavigatorItemIcon,
  NavigatorItemLabel,
  NavigatorLeafIndicator,
} from "@k8slens/navigator-components";
import {
  getNavigatorItemKind,
  getNavigatorItemKindInjectableBunch,
  type NavigatorItemProps,
  useItemDrillDown,
  useItemHasChildren,
  useItemIsOpen,
} from "@k8slens/navigator-contracts";
import { useInject } from "@k8slens/use-inject";
import { computed } from "mobx";
import { viewIcons } from "./governance-tab.injectable";
import { openGovernanceViewInjectable } from "./navigation.injectable";
import { type GovernanceView, governanceViews } from "./views";

interface GovernanceItem {
  readonly id: string;
  readonly name: string;
}

interface ViewItem {
  readonly id: GovernanceView;
  readonly name: string;
  readonly description: string;
}

export const governanceItemKind = getNavigatorItemKind<GovernanceItem, [clusterId: string]>()("governance");
export const governanceViewItemKind = getNavigatorItemKind<ViewItem, [clusterId: string, governanceId: string]>()("governance-view");

const GovernanceRow = ({ kind, ids, item }: NavigatorItemProps<GovernanceItem, typeof clusterNavigatorItemKind>) => {
  const isOpen = useItemIsOpen(kind, ...ids);
  const hasChildren = useItemHasChildren(kind, ...ids);
  const drillDown = useItemDrillDown(kind, ...ids);

  return (
    <>
      {hasChildren ? <NavigatorBranchIndicator isOpen={isOpen} /> : <NavigatorLeafIndicator />}
      <NavigatorItemIcon>
        <SecurityIcon />
      </NavigatorItemIcon>
      <NavigatorItemLabel $tooltip="Permissions, admission policies, network reachability and the policy lab">{item.name}</NavigatorItemLabel>
      <NavigatorItemActions>
        <NavigatorDrillDownButton $onClick={drillDown} />
      </NavigatorItemActions>
    </>
  );
};

const ViewRow = ({ ids, item }: NavigatorItemProps<ViewItem, typeof governanceItemKind>) => {
  const openView = useInject(openGovernanceViewInjectable)();
  const Icon = viewIcons[item.id];
  const [clusterId] = ids;

  return (
    <>
      <NavigatorLeafIndicator />
      <NavigatorItemIcon>
        <Icon />
      </NavigatorItemIcon>
      <NavigatorItemLabel $tooltip={item.description} onClick={() => void openView(clusterId, item.id)}>
        {item.name}
      </NavigatorItemLabel>
    </>
  );
};

export const governanceNavigatorItems = getNavigatorItemKindInjectableBunch({
  kind: governanceItemKind,
  parentKind: clusterNavigatorItemKind,
  description: "Governance of a cluster: who may do what, what admission policy requires, and what may talk to what.",
  items: {
    instantiate: () => async () => computed(() => [{ id: "governance", name: "Governance" }]),
  },
  Component: GovernanceRow,
});

export const governanceViewNavigatorItems = getNavigatorItemKindInjectableBunch({
  kind: governanceViewItemKind,
  parentKind: governanceItemKind,
  description: "One governance view of a cluster, which opens in a tab.",
  items: {
    instantiate: () => async () =>
      computed(() => governanceViews.map((view, index) => ({ id: view.view, name: view.title, description: view.description, orderNumber: index }))),
  },
  Component: ViewRow,
});
