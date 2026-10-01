/** The three views of the extension, and how a tab names the view and cluster it shows. */

import { getNavigationTargetKind } from "@k8slens/navigation-contracts";
import { getTabKind } from "@k8slens/tab-contracts";

export type GovernanceView = "rbac" | "policies" | "network" | "lab";

export const governanceViews: readonly { readonly view: GovernanceView; readonly title: string; readonly short: string; readonly description: string }[] = [
  { view: "rbac", title: "Service account permissions", short: "Permissions", description: "What every service account can do, and how risky it is" },
  { view: "policies", title: "Admission policies", short: "Policies", description: "Kyverno and OPA Gatekeeper policies, and what they restrict" },
  { view: "network", title: "Network reachability", short: "Reachability", description: "Which pods can reach which, by NetworkPolicy, Cilium and Calico" },
  { view: "lab", title: "Policy lab", short: "Lab", description: "Draft policies and test manifests, checked against the cluster before they are applied" },
];

export const viewInfo = (view: GovernanceView) => governanceViews.find((entry) => entry.view === view)!;

/**
 * A tab opened by its id alone: the id says the view and the cluster, so a tab Lens restores after
 * a restart needs nothing kept beside it.
 */
export const governanceTabKind = getTabKind()("governance-view");

export const tabIdOf = (view: GovernanceView, clusterId: string) => `${view}|${clusterId}`;

export const parseTabId = (tabId: string): { view: GovernanceView; clusterId: string } | undefined => {
  const separator = tabId.indexOf("|");
  const view = tabId.slice(0, separator) as GovernanceView;

  return separator > 0 && governanceViews.some((entry) => entry.view === view) ? { view, clusterId: tabId.slice(separator + 1) } : undefined;
};

export const governanceNavigationTargetKind = getNavigationTargetKind<{ clusterId: string; view: GovernanceView }>()("real-governance-view");
