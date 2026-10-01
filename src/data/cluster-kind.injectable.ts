import { connectClusterInjectionToken } from "@k8slens/cluster-contracts";
import { getInjectable2 } from "@k8slens/injectable";
import { kubeResourceKindIsServedInjectionToken, kubeResourcesInjectionToken } from "@k8slens/kubernetes-contracts";
import type { Subscribable, Subscription } from "@k8slens/subscribable";
import { computed, createAtom, type IComputedValue, observable, runInAction } from "mobx";
import { watchSpecOf } from "./watch-specs";

export type KindLoad =
  | { readonly state: "loading" }
  | { readonly state: "ready"; readonly items: readonly unknown[] }
  /** A custom resource the cluster does not serve: its operator is not installed. */
  | { readonly state: "absent" }
  | { readonly state: "failed"; readonly error: string };

type Internal =
  | { readonly state: "loading" }
  | { readonly state: "ready"; readonly items: IComputedValue<readonly unknown[]> }
  | { readonly state: "absent" }
  | { readonly state: "failed"; readonly error: string };

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

export const clusterKindKey = (clusterId: string, watchKey: string) => `${clusterId}|${watchKey}`;

/**
 * The resources of one kind on one cluster, live exactly while something observes the result:
 * the watch starts with the first observer and ends with the last, so a closed view costs the
 * cluster nothing. Keyed by `clusterKindKey(clusterId, watchKey)`.
 */
export const clusterKindInjectable = getInjectable2({
  id: "real-governance-cluster-kind",
  consumptions: [kubeResourcesInjectionToken, kubeResourceKindIsServedInjectionToken, connectClusterInjectionToken],

  instantiate: (di) => {
    const kubeResources = di.inject(kubeResourcesInjectionToken)();
    const kindIsServed = di.inject(kubeResourceKindIsServedInjectionToken)();
    const connectCluster = di.inject(connectClusterInjectionToken);

    return (key: string): IComputedValue<KindLoad> => {
      const separator = key.indexOf("|");
      const clusterId = key.slice(0, separator);
      const spec = watchSpecOf(key.slice(separator + 1));
      const current = observable.box<Internal>({ state: "loading" }, { deep: false });
      const subscriptions: Subscription<unknown>[] = [];
      // Tells a start still waiting on the cluster that it has since been stopped.
      let generation = 0;

      const set = (value: Internal, at: number) => {
        if (at === generation) runInAction(() => current.set(value));
      };

      const start = () => {
        const at = ++generation;

        void (async () => {
          try {
            await connectCluster(clusterId);

            if (spec.optional) {
              const served = kindIsServed(spec.kind as never, spec.apiVersion as never, clusterId).subscribe();

              served.claim();

              try {
                const isServed = (await served.value).get();

                if (!isServed) return set({ state: "absent" }, at);
              } finally {
                served.dispose();
              }
            }

            if (at !== generation) return;

            const subscribable = kubeResources(spec.kind as never, spec.apiVersion as never, clusterId) as unknown as Subscribable<readonly unknown[]>;
            const subscription = subscribable.subscribe();

            subscription.claim();
            subscriptions.push(subscription);
            set({ state: "ready", items: await subscription.value }, at);
          } catch (error) {
            set({ state: "failed", error: messageOf(error) }, at);
          }
        })();
      };

      const stop = () => {
        generation++;
        subscriptions.splice(0).forEach((subscription) => subscription.dispose());
        runInAction(() => current.set({ state: "loading" }));
      };

      const liveness = createAtom(`real-governance-${key}`, start, stop);

      return computed((): KindLoad => {
        liveness.reportObserved();

        const value = current.get();

        return value.state === "ready" ? { state: "ready", items: value.items.get() } : value;
      });
    };
  },
});

export interface KindsSnapshot<K extends string> {
  readonly items: Readonly<Record<K, readonly unknown[]>>;
  /** Some kind has not answered yet. */
  readonly loading: boolean;
  /** The kinds that have not answered yet, by what the user is told they are. */
  readonly pending: readonly { readonly key: K; readonly label: string }[];
  readonly absent: ReadonlySet<K>;
  readonly failures: readonly { readonly key: K; readonly label: string; readonly error: string }[];
}

/** Reads several kinds of one cluster at once, from inside a computed. */
export const readKinds = <K extends string>(
  loadOf: (key: string) => IComputedValue<KindLoad>,
  clusterId: string,
  keys: readonly K[],
): KindsSnapshot<K> => {
  const items = {} as Record<K, readonly unknown[]>;
  const absent = new Set<K>();
  const failures: { key: K; label: string; error: string }[] = [];
  const pending: { key: K; label: string }[] = [];

  for (const key of keys) {
    const load = loadOf(clusterKindKey(clusterId, key)).get();

    items[key] = load.state === "ready" ? load.items : [];

    if (load.state === "loading") pending.push({ key, label: watchSpecOf(key).label });
    if (load.state === "absent") absent.add(key);
    if (load.state === "failed") failures.push({ key, label: watchSpecOf(key).label, error: load.error });
  }

  return { items, loading: pending.length > 0, pending, absent, failures };
};
