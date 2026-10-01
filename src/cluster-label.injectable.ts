import { clusterNameReactiveInjectionToken } from "@k8slens/cluster-contracts";
import { getInjectable2 } from "@k8slens/injectable";
import { computed, type IComputedValue, observable, runInAction } from "mobx";

/** What a cluster is called, following renames; its id until Lens has said. One per cluster. */
export const clusterLabelInjectable = getInjectable2({
  id: "real-governance-cluster-label",
  consumptions: [clusterNameReactiveInjectionToken],

  instantiate: (di) => {
    const clusterNameOf = di.inject(clusterNameReactiveInjectionToken);

    return (clusterId: string) => {
      const name = observable.box<IComputedValue<string> | undefined>(undefined, { deep: false });

      void clusterNameOf(clusterId).then((computedName) => runInAction(() => name.set(computedName)));

      return computed(() => name.get()?.get() ?? clusterId.slice(0, 8));
    };
  },
});
