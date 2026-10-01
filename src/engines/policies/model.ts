/**
 * Admission policies of every engine, normalized to one shape: what a rule requires, what it does
 * when a resource does not comply, and which resources it applies to.
 */

import type { RuleCheck } from "./check";

export type PolicyEngine = "kyverno" | "kyverno-cel" | "gatekeeper";

export const engineLabel: Record<PolicyEngine, string> = {
  kyverno: "Kyverno",
  "kyverno-cel": "Kyverno CEL",
  gatekeeper: "OPA Gatekeeper",
};

/**
 * What happens to a resource that does not comply.
 * - `enforce`: the request is rejected.
 * - `audit`: allowed, recorded as a violation in reports or the constraint's status.
 * - `warn`: allowed, the client is shown a warning.
 * - `mutate` / `generate`: the policy changes the resource, or creates others; nothing is refused.
 *
 * Image verification is `enforce` or `audit` like any validation, by its failure action.
 */
export type PolicyEffect = "enforce" | "audit" | "warn" | "mutate" | "generate";

export const effectLabel: Record<PolicyEffect, string> = {
  enforce: "Blocks",
  audit: "Audits",
  warn: "Warns",
  mutate: "Mutates",
  generate: "Generates",
};

/** A resource as a simulation asks about it: one that is being created, updated or deleted. */
export interface SimulationTarget {
  readonly kind: string;
  /** API group of the kind, "" for the core group. */
  readonly group: string;
  /** Plural resource name, as CEL policies and RBAC name kinds. */
  readonly resource: string;
  readonly namespace?: string;
  readonly namespaceLabels: Readonly<Record<string, string>>;
  readonly name?: string;
  readonly labels: Readonly<Record<string, string>>;
  readonly operation: "CREATE" | "UPDATE" | "DELETE" | "CONNECT";
}

export type MatchOutcome =
  | { readonly applies: true; readonly reasons: readonly string[]; readonly caveats: readonly string[] }
  | { readonly applies: false; readonly reason: string };

/** One line of what a rule asks of a resource, in words, with the source it was read from. */
export interface Requirement {
  readonly text: string;
  /** Code the requirement is written in: a CEL expression, Rego, a JSON patch. */
  readonly code?: string;
  readonly codeLanguage?: "cel" | "rego" | "yaml" | "json" | "jmespath";
}

export interface PolicyRef {
  readonly engine: PolicyEngine;
  readonly kind: string;
  readonly name: string;
  readonly namespace?: string;
}

export const policyRefKey = (ref: PolicyRef) => `${ref.engine}:${ref.kind}:${ref.namespace ?? ""}/${ref.name}`;

export interface NormalizedRule {
  readonly id: string;
  readonly policy: PolicyRef;
  readonly name: string;
  /** validate, mutate, generate, verifyImages, cel, rego, … as the engine calls it. */
  readonly type: string;
  /** The effect where no namespace override applies. */
  readonly effect: PolicyEffect;
  /** The effect for a resource in this namespace, after per-namespace overrides. */
  readonly effectIn: (namespace: string | undefined, namespaceLabels: Readonly<Record<string, string>>) => PolicyEffect;
  readonly message?: string;
  /** Which resources the rule is for, in words. */
  readonly scope: readonly string[];
  readonly requirements: readonly Requirement[];
  /** Conditions that only the actual request can settle, such as who sends it. */
  readonly conditions: readonly string[];
  readonly matches: (target: SimulationTarget) => MatchOutcome;
  /** Whether a resource complies, where the lab can tell without the engine itself. */
  readonly check?: (resource: unknown, operation: SimulationTarget["operation"]) => RuleCheck;
  /** Rules the engine generated for controllers, such as Kyverno's auto-gen rules for Deployments. */
  readonly autogen?: boolean;
}

export interface NormalizedPolicy {
  readonly ref: PolicyRef;
  readonly title: string;
  readonly description?: string;
  readonly category?: string;
  readonly severity?: string;
  /** Whether the engine reports it ready, and why not when it does not. */
  readonly ready: { readonly ok: boolean; readonly message?: string } | undefined;
  readonly rules: readonly NormalizedRule[];
  /** Whether existing resources are scanned in the background, so reports cover what is already there. */
  readonly background?: boolean;
  /** The engine's own violation count, where it keeps one (Gatekeeper constraints). */
  readonly reportedViolations?: number;
  readonly notes: readonly string[];
  readonly raw: unknown;
}

/** One result of a policy report, or of a Gatekeeper constraint's audit. */
export interface PolicyResult {
  readonly engine: PolicyEngine;
  readonly policy: string;
  /** Namespace of a namespaced policy, when the result says. */
  readonly policyNamespace?: string;
  readonly rule?: string;
  readonly result: "pass" | "fail" | "warn" | "error" | "skip";
  readonly message?: string;
  readonly severity?: string;
  readonly resource: { readonly kind: string; readonly apiVersion?: string; readonly namespace?: string; readonly name: string };
  readonly timestamp?: number;
}

/** Kinds a simulation can be asked about, with what CEL and RBAC call them. */
export const simulationKinds: readonly { readonly kind: string; readonly group: string; readonly resource: string; readonly namespaced: boolean }[] = [
  { kind: "Pod", group: "", resource: "pods", namespaced: true },
  { kind: "Deployment", group: "apps", resource: "deployments", namespaced: true },
  { kind: "StatefulSet", group: "apps", resource: "statefulsets", namespaced: true },
  { kind: "DaemonSet", group: "apps", resource: "daemonsets", namespaced: true },
  { kind: "ReplicaSet", group: "apps", resource: "replicasets", namespaced: true },
  { kind: "Job", group: "batch", resource: "jobs", namespaced: true },
  { kind: "CronJob", group: "batch", resource: "cronjobs", namespaced: true },
  { kind: "Service", group: "", resource: "services", namespaced: true },
  { kind: "Ingress", group: "networking.k8s.io", resource: "ingresses", namespaced: true },
  { kind: "ConfigMap", group: "", resource: "configmaps", namespaced: true },
  { kind: "Secret", group: "", resource: "secrets", namespaced: true },
  { kind: "ServiceAccount", group: "", resource: "serviceaccounts", namespaced: true },
  { kind: "PersistentVolumeClaim", group: "", resource: "persistentvolumeclaims", namespaced: true },
  { kind: "NetworkPolicy", group: "networking.k8s.io", resource: "networkpolicies", namespaced: true },
  { kind: "Role", group: "rbac.authorization.k8s.io", resource: "roles", namespaced: true },
  { kind: "RoleBinding", group: "rbac.authorization.k8s.io", resource: "rolebindings", namespaced: true },
  { kind: "Namespace", group: "", resource: "namespaces", namespaced: false },
  { kind: "ClusterRole", group: "rbac.authorization.k8s.io", resource: "clusterroles", namespaced: false },
  { kind: "ClusterRoleBinding", group: "rbac.authorization.k8s.io", resource: "clusterrolebindings", namespaced: false },
  { kind: "Node", group: "", resource: "nodes", namespaced: false },
];

/** A kind not in the list: its resource name guessed the way kubectl's default plural rules would. */
export const kindInfo = (kind: string) => {
  const known = simulationKinds.find((candidate) => candidate.kind.toLowerCase() === kind.toLowerCase());

  if (known) return known;

  const lower = kind.toLowerCase();
  const resource = lower.endsWith("s") ? `${lower}es` : lower.endsWith("y") ? `${lower.slice(0, -1)}ies` : `${lower}s`;

  return { kind, group: "", resource, namespaced: true };
};
