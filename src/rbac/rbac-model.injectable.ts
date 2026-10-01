import { getInjectable2 } from "@k8slens/injectable";
import { computed } from "mobx";
import { clusterKindInjectable, readKinds } from "../data/cluster-kind.injectable";
import {
  type AccessRequest,
  authorize,
  type BindingLike,
  commonResources,
  type Grant,
  grantsOf,
  indexRbac,
  isImplicitGroupGrant,
  type KnownResource,
  matrixVerbs,
  namespacesAllowed,
  parseResource,
  type Principal,
  principalKey,
  principalLabel,
  principalsNamedByBindings,
  resourceLabel,
  resourcesNamedBy,
  type RiskFinding,
  risksOf,
  riskScore,
  type RoleLike,
  type ServiceAccountLike,
  type Severity,
  worstSeverity,
} from "../engines/rbac";
import { type RiskFilter, rbacStateInjectable } from "./rbac-state.injectable";

const keys = ["serviceAccounts", "roles", "clusterRoles", "roleBindings", "clusterRoleBindings", "pods", "namespaces"] as const;

/** What every permission is worked out from: without all four, an account's grants are unknown, not empty. */
const rbacKeys: ReadonlySet<(typeof keys)[number]> = new Set(["roles", "clusterRoles", "roleBindings", "clusterRoleBindings"]);

/**
 * Whether the permissions can be worked out: "reading" while a role or binding list has not
 * answered, "unreadable" when the cluster's credentials may not list one of them.
 */
export type RbacAccess =
  | { readonly state: "ready" }
  | { readonly state: "reading"; readonly waitingFor: readonly string[] }
  | { readonly state: "unreadable"; readonly unreadable: readonly { readonly label: string; readonly error: string }[] };

interface PodLike {
  readonly metadata: { readonly name: string; readonly namespace: string };
  readonly spec?: { readonly serviceAccountName?: string; readonly automountServiceAccountToken?: boolean };
  readonly status?: { readonly phase?: string };
}

export interface AccountSummary {
  readonly key: string;
  readonly principal: Extract<Principal, { type: "ServiceAccount" }>;
  readonly label: string;
  readonly automount: boolean;
  readonly grants: readonly Grant[];
  readonly risks: readonly RiskFinding[];
  readonly score: number;
  readonly worst?: Severity;
  readonly pods: readonly PodLike[];
}

export type MatrixLevel = "all" | "some" | "none";

export interface MatrixRow {
  readonly resource: KnownResource;
  readonly label: string;
  readonly cells: readonly { readonly verb: string; readonly level: MatrixLevel; readonly namespaces: readonly string[] }[];
}

export interface WhoCanEntry {
  readonly principal: Principal;
  readonly label: string;
  readonly matches: ReturnType<typeof authorize>["matches"];
}

const isSystemPrincipal = (principal: Principal) =>
  principal.type === "ServiceAccount" ? principal.namespace === "kube-system" : principal.name.startsWith("system:");

/** The permissions of a cluster's service accounts, as the RBAC view shows them. One per cluster. */
export const rbacModelInjectable = getInjectable2({
  id: "real-governance-rbac-model",

  instantiate: (di) => {
    const loadOf = di.inject(clusterKindInjectable);
    const stateOf = di.inject(rbacStateInjectable);

    return (clusterId: string) => {
      const state = stateOf(clusterId);
      const snapshot = computed(() => readKinds(loadOf, clusterId, keys));

      const access = computed((): RbacAccess => {
        const { failures, pending } = snapshot.get();
        const unreadable = failures.filter((failure) => rbacKeys.has(failure.key));

        if (unreadable.length > 0) return { state: "unreadable", unreadable };

        const waiting = pending.filter((entry) => rbacKeys.has(entry.key));

        return waiting.length > 0 ? { state: "reading", waitingFor: waiting.map((entry) => entry.label) } : { state: "ready" };
      });

      const index = computed(() => {
        const { items } = snapshot.get();

        return indexRbac({
          roles: items.roles as RoleLike[],
          clusterRoles: items.clusterRoles as RoleLike[],
          roleBindings: items.roleBindings as BindingLike[],
          clusterRoleBindings: items.clusterRoleBindings as BindingLike[],
        });
      });

      const podsByAccount = computed(() => {
        const byAccount = new Map<string, PodLike[]>();

        for (const pod of snapshot.get().items.pods as PodLike[]) {
          if (pod.status?.phase === "Succeeded" || pod.status?.phase === "Failed") continue;

          const key = `${pod.metadata.namespace}/${pod.spec?.serviceAccountName ?? "default"}`;

          byAccount.set(key, [...(byAccount.get(key) ?? []), pod]);
        }

        return byAccount;
      });

      const accounts = computed((): AccountSummary[] => {
        const current = index.get();

        return (snapshot.get().items.serviceAccounts as ServiceAccountLike[])
          .map((account) => {
            const principal = { type: "ServiceAccount" as const, namespace: account.metadata.namespace!, name: account.metadata.name };
            const grants = grantsOf(current, principal);
            const risks = risksOf(grants);

            return {
              key: principalKey(principal),
              principal,
              label: principalLabel(principal),
              automount: account.automountServiceAccountToken !== false,
              grants,
              risks,
              score: riskScore(risks),
              worst: worstSeverity(risks),
              pods: podsByAccount.get().get(`${principal.namespace}/${principal.name}`) ?? [],
            };
          })
          .sort((a, b) => b.score - a.score || a.label.localeCompare(b.label));
      });

      const namespaces = computed(() =>
        [...new Set((snapshot.get().items.namespaces as { metadata: { name: string } }[]).map((namespace) => namespace.metadata.name))].sort(),
      );

      const visibleAccounts = computed(() => {
        const search = state.search.get().trim().toLowerCase();
        const namespace = state.namespace.get();

        return accounts
          .get()
          .filter(
            (account) =>
              (!namespace || account.principal.namespace === namespace) &&
              (!search || account.label.toLowerCase().includes(search)) &&
              (state.riskFilter.size === 0 || state.riskFilter.has(account.worst ?? "none")),
          );
      });

      /** Accounts by their worst finding, and of those how many a running pod acts as. */
      const tally = computed(() => {
        const all = accounts.get();
        const of = (risk: RiskFilter) => all.filter((account) => (account.worst ?? "none") === risk);
        const tile = (risk: RiskFilter) => ({ accounts: of(risk).length, withPods: of(risk).filter((account) => account.pods.length > 0).length });

        return {
          accounts: all.length,
          critical: of("critical").length,
          high: of("high").length,
          bySeverity: { critical: tile("critical"), high: tile("high"), medium: tile("medium"), low: tile("low"), none: tile("none") } as Record<RiskFilter, { accounts: number; withPods: number }>,
        };
      });

      const selected = computed(() => accounts.get().find((account) => account.key === state.selected.get()));

      const visibleGrants = computed(() => {
        const account = selected.get();

        if (!account) return [];

        return state.showImplicit.get() ? account.grants : account.grants.filter((grant) => !isImplicitGroupGrant(grant));
      });

      /** Grants through groups every service account is in, hidden unless asked for. */
      const implicitGrantCount = computed(() => (selected.get()?.grants ?? []).filter(isImplicitGroupGrant).length);

      const matrix = computed((): MatrixRow[] => {
        const account = selected.get();

        if (!account) return [];

        const scope = state.matrixScope.get();
        const seen = new Set<string>();
        const resources = [...commonResources, ...resourcesNamedBy(account.grants)].filter((resource) => {
          const label = resourceLabel(resource);

          if (seen.has(label)) return false;

          seen.add(label);

          return true;
        });

        const rows = resources.map((resource): MatrixRow => ({
          resource,
          label: resourceLabel(resource),
          cells: matrixVerbs.map((verb) => {
            const request = { verb, apiGroup: resource.group, resource: resource.resource, subresource: resource.subresource };

            if (scope !== "cluster") {
              const allowed = authorize(account.grants, { type: "resource", ...request, namespace: resource.namespaced ? scope : undefined }).allowed;

              return { verb, level: allowed ? "all" : "none", namespaces: [] };
            }

            const allowedIn = namespacesAllowed(resource.namespaced ? account.grants : account.grants.filter((grant) => grant.scope.type === "cluster"), request);

            return allowedIn === "all"
              ? { verb, level: "all", namespaces: [] }
              : { verb, level: allowedIn.length > 0 ? "some" : "none", namespaces: allowedIn };
          }),
        }));

        return state.matrixAllRows.get() ? rows : rows.filter((row) => row.cells.some((cell) => cell.level !== "none"));
      });

      const nonResourceRules = computed(() =>
        (selected.get()?.grants ?? []).filter((grant) => grant.scope.type === "cluster").flatMap((grant) =>
          grant.rules.filter((rule) => (rule.nonResourceURLs ?? []).length > 0).map((rule) => ({ grant, rule })),
        ),
      );

      const requestOf = (form: { verb: string; resource: string; namespace: string; name?: string }): AccessRequest | undefined => {
        const verb = form.verb.trim();

        if (!verb) return undefined;

        if (form.resource.trim().startsWith("/")) return { type: "nonResource", verb, path: form.resource.trim() };

        const parsed = parseResource(form.resource);

        if (!parsed) return undefined;

        return {
          type: "resource",
          verb,
          apiGroup: parsed.group,
          resource: parsed.resource,
          subresource: parsed.subresource,
          namespace: form.namespace.trim() || undefined,
          name: form.name?.trim() || undefined,
        };
      };

      const canI = computed(() => {
        const account = selected.get();
        const request = requestOf(state.canI);

        return account && request ? { request, ...authorize(account.grants, request) } : undefined;
      });

      const whoCan = computed(() => {
        const request = requestOf(state.whoCan);

        if (!request) return undefined;

        const current = index.get();
        const fromAccounts = accounts.get().map((account) => ({ principal: account.principal as Principal, grants: account.grants }));
        const known = new Set(fromAccounts.map((entry) => principalKey(entry.principal)));
        const others = principalsNamedByBindings(current.data)
          .filter((principal) => !known.has(principalKey(principal)))
          .map((principal) => ({ principal, grants: grantsOf(current, principal) }));

        const entries: WhoCanEntry[] = [...fromAccounts, ...others]
          .filter((entry) => state.whoCan.includeSystem || !isSystemPrincipal(entry.principal))
          .flatMap((entry) => {
            const result = authorize(entry.grants, request);

            return result.allowed ? [{ principal: entry.principal, label: principalLabel(entry.principal), matches: result.matches }] : [];
          })
          .sort((a, b) => a.principal.type.localeCompare(b.principal.type) || a.label.localeCompare(b.label));

        return { request, entries };
      });

      return {
        clusterId,
        state,
        snapshot,
        access,
        accounts,
        visibleAccounts,
        namespaces,
        tally,
        selected,
        visibleGrants,
        implicitGrantCount,
        matrix,
        matrixVerbs,
        nonResourceRules,
        canI,
        whoCan,
        knownResources: computed(() => [...new Set([...commonResources, ...resourcesNamedBy(selected.get()?.grants ?? [])].map(resourceLabel))].sort()),
      };
    };
  },
});

export type RbacModel = ReturnType<ReturnType<(typeof rbacModelInjectable)["instantiate"]>>;
