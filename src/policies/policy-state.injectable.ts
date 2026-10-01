import { getInjectable2 } from "@k8slens/injectable";
import { action, observable } from "mobx";
import type { PolicyEffect, PolicyEngine } from "../engines/policies/model";

export type PolicySubView = "policies" | "simulate" | "violations";

/** What the user has chosen in a cluster's policies view. One per cluster, kept while Lens runs. */
export const policyStateInjectable = getInjectable2({
  id: "real-governance-policy-state",

  instantiate: () => (_clusterId: string) => {
    const state = {
      subView: observable.box<PolicySubView>("policies"),
      search: observable.box(""),
      engines: observable.set<PolicyEngine>(),
      effects: observable.set<PolicyEffect>(),
      expanded: observable.set<string>(),
      simulation: observable({ kind: "Pod", namespace: "default", labels: "", name: "", operation: "CREATE" as "CREATE" | "UPDATE" | "DELETE" }),
      showSkipped: observable.box(false),
      violationSearch: observable.box(""),
      violationResults: observable.set<"fail" | "warn" | "error">(["fail", "warn", "error"]),
    };

    const toggle = <T>(set: Set<T>, value: T) => (set.has(value) ? set.delete(value) : set.add(value));

    return {
      ...state,
      setSubView: action((view: PolicySubView) => state.subView.set(view)),
      setSearch: action((value: string) => state.search.set(value)),
      toggleEngine: action((engine: PolicyEngine) => toggle(state.engines, engine)),
      toggleEffect: action((effect: PolicyEffect) => toggle(state.effects, effect)),
      toggleExpanded: action((id: string) => toggle(state.expanded, id)),
      setSimulation: action((patch: Partial<typeof state.simulation>) => Object.assign(state.simulation, patch)),
      setShowSkipped: action((value: boolean) => state.showSkipped.set(value)),
      setViolationSearch: action((value: string) => state.violationSearch.set(value)),
      toggleViolationResult: action((result: "fail" | "warn" | "error") => toggle(state.violationResults, result)),

      /** Opens the simulator on a resource, as a menu asks. */
      simulateResource: action((kind: string, namespace: string | undefined, name: string, labels: Record<string, string>) => {
        state.subView.set("simulate");
        Object.assign(state.simulation, {
          kind,
          namespace: namespace ?? "",
          name,
          labels: Object.entries(labels).map(([key, value]) => `${key}=${value}`).join(", "),
          operation: "UPDATE",
        });
      }),

      /** Shows one policy, expanded, as a violation's link asks. */
      showPolicy: action((id: string, name: string) => {
        state.subView.set("policies");
        state.search.set(name);
        state.engines.clear();
        state.effects.clear();
        state.expanded.add(id);
      }),
    };
  },
});

export type PolicyState = ReturnType<ReturnType<(typeof policyStateInjectable)["instantiate"]>>;
