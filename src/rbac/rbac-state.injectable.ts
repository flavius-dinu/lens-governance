import { getInjectable2 } from "@k8slens/injectable";
import { action, observable } from "mobx";
import type { Severity } from "../engines/rbac";

/** What the account list can be narrowed to: a severity, or accounts with no finding at all. */
export type RiskFilter = Severity | "none";

export type RbacSubView = "accounts" | "who-can";

/** What the user has chosen in a cluster's permissions view. One per cluster, kept while Lens runs. */
export const rbacStateInjectable = getInjectable2({
  id: "real-governance-rbac-state",

  instantiate: () => (_clusterId: string) => {
    const state = {
      subView: observable.box<RbacSubView>("accounts"),
      search: observable.box(""),
      namespace: observable.box(""),
      /** Shown when empty: every account. */
      riskFilter: observable.set<RiskFilter>(),
      selected: observable.box<string | undefined>(undefined),
      showImplicit: observable.box(false),
      /** "cluster", or the namespace the matrix is for. */
      matrixScope: observable.box("cluster"),
      matrixAllRows: observable.box(false),
      canI: observable({ verb: "get", resource: "secrets", namespace: "", name: "" }),
      whoCan: observable({ verb: "get", resource: "secrets", namespace: "", includeSystem: false }),
    };

    return {
      ...state,
      setSubView: action((view: RbacSubView) => state.subView.set(view)),
      setSearch: action((value: string) => state.search.set(value)),
      setNamespace: action((value: string) => state.namespace.set(value)),
      /** Shows only these severities, or every account when given none. */
      showRisks: action((risks: readonly RiskFilter[]) => {
        state.riskFilter.replace(risks);
        state.subView.set("accounts");
      }),
      /** A dashboard tile: shows its severity alone, or everything again when it is already alone. */
      toggleRiskTile: action((risk: RiskFilter) => {
        const alone = state.riskFilter.size === 1 && state.riskFilter.has(risk);

        state.riskFilter.replace(alone ? [] : [risk]);
        state.subView.set("accounts");
      }),
      select: action((key: string | undefined) => {
        state.selected.set(key);
        state.matrixScope.set("cluster");
      }),
      setShowImplicit: action((value: boolean) => state.showImplicit.set(value)),
      setMatrixScope: action((value: string) => state.matrixScope.set(value)),
      setMatrixAllRows: action((value: boolean) => state.matrixAllRows.set(value)),
      setCanI: action((patch: Partial<typeof state.canI>) => Object.assign(state.canI, patch)),
      setWhoCan: action((patch: Partial<typeof state.whoCan>) => Object.assign(state.whoCan, patch)),

      /** Opens the view on one service account, as a menu or details section asks. */
      focusServiceAccount: action((namespace: string, name: string) => {
        state.subView.set("accounts");
        state.search.set("");
        state.namespace.set("");
        state.riskFilter.clear();
        state.selected.set(`ServiceAccount:${namespace}/${name}`);
        state.matrixScope.set("cluster");
      }),
    };
  },
});

export type RbacState = ReturnType<ReturnType<(typeof rbacStateInjectable)["instantiate"]>>;
