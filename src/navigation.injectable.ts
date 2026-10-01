import { connectClusterInjectionToken } from "@k8slens/cluster-contracts";
import { getInjectable2 } from "@k8slens/injectable";
import { mainViewTabHostKind } from "@k8slens/main-view-contracts";
import { getNavigationTargetInjectableBunch, isNavigationSupersededError, navigateToInjectionToken } from "@k8slens/navigation-contracts";
import { showErrorNotificationInjectionToken } from "@k8slens/notifications-contracts";
import { focusTabInjectionToken, openTabInjectionToken, tabIsOpenInjectionToken } from "@k8slens/tab-contracts";
import { governanceNavigationTargetKind, governanceTabKind, type GovernanceView, tabIdOf, viewInfo } from "./views";

export const governanceNavigationTarget = getNavigationTargetInjectableBunch({
  kind: governanceNavigationTargetKind,

  preconditions: [
    {
      consumptions: [connectClusterInjectionToken],
      instantiate: (di) => {
        const connectCluster = di.inject(connectClusterInjectionToken);

        return () => ({ clusterId }) => connectCluster(clusterId);
      },
    },
  ],

  navigate: {
    consumptions: [openTabInjectionToken, focusTabInjectionToken, tabIsOpenInjectionToken],
    instantiate: (di) => {
      const openTab = di.inject(openTabInjectionToken.for(mainViewTabHostKind).for(governanceTabKind).for(di.scopeIds))();
      const focusTab = di.inject(focusTabInjectionToken.for(mainViewTabHostKind).for(governanceTabKind).for(di.scopeIds))();
      const isOpen = di.inject(tabIsOpenInjectionToken.for(mainViewTabHostKind).for(governanceTabKind).for(di.scopeIds))();

      return () => async ({ clusterId, view }) => {
        const tabId = tabIdOf(view, clusterId);

        if (await isOpen({ tabId })) await focusTab({ tabId });
        else await openTab({ tabId });
      };
    },
  },

  describe: ({ view }) => viewInfo(view).title,
});

/** Takes the user to a view of a cluster, connecting it first, and says so when that fails. */
export const openGovernanceViewInjectable = getInjectable2({
  id: "real-governance-open-view",
  consumptions: [navigateToInjectionToken, showErrorNotificationInjectionToken],

  instantiate: (di) => {
    const navigateTo = di.inject(navigateToInjectionToken.for(governanceNavigationTargetKind))();
    const showErrorNotification = di.inject(showErrorNotificationInjectionToken)();

    return () => async (clusterId: string, view: GovernanceView) => {
      try {
        await navigateTo({ clusterId, view });
      } catch (error) {
        if (!isNavigationSupersededError(error)) showErrorNotification(error as Error);
      }
    };
  },
});
