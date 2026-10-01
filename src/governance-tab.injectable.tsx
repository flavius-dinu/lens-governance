import { Div, Span } from "@k8slens/element-components";
import { LayersIcon, NetworkIcon, PeopleIcon, PolicyIcon } from "@k8slens/icon";
import { mainViewTabHostKind } from "@k8slens/main-view-contracts";
import { getTabKindInjectableBunch, type TabProps } from "@k8slens/tab-contracts";
import { useInject } from "@k8slens/use-inject";
import { observer } from "mobx-react";
import { clusterLabelInjectable } from "./cluster-label.injectable";
import { LabView } from "./lab/lab-view";
import { NetworkView } from "./network/network-view";
import { PolicyView } from "./policies/policy-view";
import { RbacView } from "./rbac/rbac-view";
import { ErrorBoundary, Notice } from "./ui/common";
import { governanceTabKind, type GovernanceView, parseTabId, viewInfo } from "./views";

export const viewIcons: Record<GovernanceView, typeof PeopleIcon> = { rbac: PeopleIcon, policies: PolicyIcon, network: NetworkIcon, lab: LayersIcon };

const views: Record<GovernanceView, (props: { clusterId: string }) => React.ReactNode> = {
  rbac: RbacView,
  policies: PolicyView,
  network: NetworkView,
  lab: LabView,
};

const ClusterLabel = observer(({ clusterId }: { clusterId: string }) => <>{useInject(clusterLabelInjectable)(clusterId).get()}</>);

const GovernanceTitle = ({ tabId }: TabProps<typeof mainViewTabHostKind>) => {
  const parsed = parseTabId(tabId);

  if (!parsed) return <Span>Governance</Span>;

  const Icon = viewIcons[parsed.view];

  return (
    <Div $flex={{ direction: "horizontal", gap: "xs", verticalAlign: "center" }}>
      <Icon $size="s" />
      <Span>
        {viewInfo(parsed.view).short} · <ClusterLabel clusterId={parsed.clusterId} />
      </Span>
    </Div>
  );
};

const GovernanceContent = ({ tabId }: TabProps<typeof mainViewTabHostKind>) => {
  const parsed = parseTabId(tabId);

  if (!parsed) return <Notice tone="critical">This tab does not name a view of a cluster.</Notice>;

  const View = views[parsed.view];

  return (
    <ErrorBoundary label={viewInfo(parsed.view).title}>
      <View clusterId={parsed.clusterId} />
    </ErrorBoundary>
  );
};

export const governanceTab = getTabKindInjectableBunch({
  tabHostKind: mainViewTabHostKind,
  kind: governanceTabKind,
  Component: GovernanceContent,
  Title: GovernanceTitle,
});
