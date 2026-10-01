/**
 * Effective RBAC permissions of a subject, computed from Roles, ClusterRoles and their bindings
 * the way the API server's RBAC authorizer does: the union of every rule of every role bound to
 * the subject, directly or through a group it belongs to. RBAC has no deny, so a request is
 * allowed exactly when some rule covers it.
 */

export interface PolicyRule {
  readonly apiGroups?: readonly string[] | null;
  readonly resources?: readonly string[] | null;
  readonly verbs: readonly string[];
  readonly resourceNames?: readonly string[] | null;
  readonly nonResourceURLs?: readonly string[] | null;
}

interface Meta {
  readonly name: string;
  readonly namespace?: string;
  readonly uid?: string;
  readonly labels?: Readonly<Record<string, string>> | null;
  readonly annotations?: Readonly<Record<string, string>> | null;
}

export interface RoleLike {
  readonly kind?: string;
  readonly metadata: Meta;
  readonly rules?: readonly PolicyRule[] | null;
  readonly aggregationRule?: unknown;
}

export interface Subject {
  readonly kind: string;
  readonly name: string;
  readonly namespace?: string;
  readonly apiGroup?: string;
}

export interface BindingLike {
  readonly kind?: string;
  readonly metadata: Meta;
  readonly roleRef: { readonly apiGroup?: string; readonly kind: string; readonly name: string };
  readonly subjects?: readonly Subject[] | null;
}

export interface ServiceAccountLike {
  readonly metadata: Meta;
  readonly automountServiceAccountToken?: boolean | null;
  readonly secrets?: readonly { readonly name?: string }[] | null;
}

export interface RbacData {
  readonly roles: readonly RoleLike[];
  readonly clusterRoles: readonly RoleLike[];
  readonly roleBindings: readonly BindingLike[];
  readonly clusterRoleBindings: readonly BindingLike[];
}

/** Who a permission is for. A service account is also every group it is implicitly a member of. */
export type Principal =
  | { readonly type: "ServiceAccount"; readonly namespace: string; readonly name: string }
  | { readonly type: "User"; readonly name: string }
  | { readonly type: "Group"; readonly name: string };

export const principalKey = (principal: Principal) =>
  principal.type === "ServiceAccount" ? `ServiceAccount:${principal.namespace}/${principal.name}` : `${principal.type}:${principal.name}`;

export const principalLabel = (principal: Principal) =>
  principal.type === "ServiceAccount" ? `${principal.namespace}/${principal.name}` : principal.name;

export type GrantScope = { readonly type: "cluster" } | { readonly type: "namespace"; readonly namespace: string };

export interface Grant {
  readonly binding: { readonly kind: "RoleBinding" | "ClusterRoleBinding"; readonly name: string; readonly namespace?: string };
  readonly role: { readonly kind: string; readonly name: string; readonly namespace?: string };
  /** False when the binding names a role that does not exist: it grants nothing until it does. */
  readonly roleExists: boolean;
  readonly scope: GrantScope;
  /** How the binding reaches the principal: named directly, or through a group. */
  readonly via: string;
  readonly rules: readonly PolicyRule[];
}

export const scopeLabel = (scope: GrantScope) => (scope.type === "cluster" ? "cluster-wide" : `namespace ${scope.namespace}`);

/** The groups Kubernetes puts every service account token into. */
export const implicitGroupsOf = (principal: Principal): string[] =>
  principal.type === "ServiceAccount"
    ? ["system:serviceaccounts", `system:serviceaccounts:${principal.namespace}`, "system:authenticated"]
    : principal.type === "User"
      ? ["system:authenticated"]
      : [];

const subjectReaches = (subject: Subject, bindingNamespace: string | undefined, principal: Principal): string | undefined => {
  switch (subject.kind) {
    case "ServiceAccount":
      if (principal.type !== "ServiceAccount") return undefined;

      return subject.name === principal.name && (subject.namespace || bindingNamespace) === principal.namespace
        ? "service account"
        : undefined;

    case "User":
      if (principal.type === "User") return subject.name === principal.name ? "user" : undefined;
      if (principal.type === "ServiceAccount" && subject.name === `system:serviceaccount:${principal.namespace}:${principal.name}`)
        return "user name of the service account";

      return undefined;

    case "Group":
      if (principal.type === "Group") return subject.name === principal.name ? "group" : undefined;

      return implicitGroupsOf(principal).includes(subject.name) ? `group ${subject.name}` : undefined;

    default:
      return undefined;
  }
};

export interface RbacIndex {
  readonly data: RbacData;
  readonly clusterRoleByName: ReadonlyMap<string, RoleLike>;
  readonly roleByKey: ReadonlyMap<string, RoleLike>;
}

export const indexRbac = (data: RbacData): RbacIndex => ({
  data,
  clusterRoleByName: new Map(data.clusterRoles.map((role) => [role.metadata.name, role])),
  roleByKey: new Map(data.roles.map((role) => [`${role.metadata.namespace}/${role.metadata.name}`, role])),
});

const resolveRole = (index: RbacIndex, roleRef: BindingLike["roleRef"], bindingNamespace?: string) =>
  roleRef.kind === "ClusterRole" ? index.clusterRoleByName.get(roleRef.name) : index.roleByKey.get(`${bindingNamespace}/${roleRef.name}`);

/** Every binding that reaches the principal, with the rules of the role it binds. */
export const grantsOf = (index: RbacIndex, principal: Principal): Grant[] => {
  const grants: Grant[] = [];

  const consider = (binding: BindingLike, kind: "RoleBinding" | "ClusterRoleBinding") => {
    const namespace = kind === "RoleBinding" ? binding.metadata.namespace : undefined;
    const via = (binding.subjects ?? []).map((subject) => subjectReaches(subject, namespace, principal)).find(Boolean);

    if (!via) return;

    const role = resolveRole(index, binding.roleRef, namespace);

    grants.push({
      binding: { kind, name: binding.metadata.name, namespace },
      role: {
        kind: binding.roleRef.kind,
        name: binding.roleRef.name,
        namespace: binding.roleRef.kind === "Role" ? namespace : undefined,
      },
      roleExists: Boolean(role),
      scope: kind === "ClusterRoleBinding" ? { type: "cluster" } : { type: "namespace", namespace: namespace ?? "" },
      via,
      rules: role?.rules ?? [],
    });
  };

  index.data.clusterRoleBindings.forEach((binding) => consider(binding, "ClusterRoleBinding"));
  index.data.roleBindings.forEach((binding) => consider(binding, "RoleBinding"));

  return grants;
};

/** Every principal any binding names, service accounts included even when they no longer exist. */
export const principalsNamedByBindings = (data: RbacData): Principal[] => {
  const seen = new Map<string, Principal>();

  const add = (subject: Subject, bindingNamespace?: string) => {
    const principal: Principal | undefined =
      subject.kind === "ServiceAccount"
        ? { type: "ServiceAccount", namespace: subject.namespace || bindingNamespace || "", name: subject.name }
        : subject.kind === "User"
          ? { type: "User", name: subject.name }
          : subject.kind === "Group"
            ? { type: "Group", name: subject.name }
            : undefined;

    if (principal) seen.set(principalKey(principal), principal);
  };

  data.clusterRoleBindings.forEach((binding) => binding.subjects?.forEach((subject) => add(subject)));
  data.roleBindings.forEach((binding) => binding.subjects?.forEach((subject) => add(subject, binding.metadata.namespace)));

  return [...seen.values()];
};

// ---------------------------------------------------------------------------------------------
// Authorizing one request
// ---------------------------------------------------------------------------------------------

export type AccessRequest =
  | {
      readonly type: "resource";
      readonly verb: string;
      readonly apiGroup: string;
      readonly resource: string;
      readonly subresource?: string;
      /** Undefined for a cluster-scoped resource, or for "in every namespace" (list --all-namespaces). */
      readonly namespace?: string;
      readonly name?: string;
    }
  | { readonly type: "nonResource"; readonly verb: string; readonly path: string };

const verbMatches = (rule: PolicyRule, verb: string) => rule.verbs.includes("*") || rule.verbs.includes(verb);

const groupMatches = (rule: PolicyRule, group: string) => (rule.apiGroups ?? []).some((candidate) => candidate === "*" || candidate === group);

// The authorizer's own ResourceMatches: "pods" does not cover "pods/log"; "*" covers everything;
// "*/scale" covers the scale subresource of every resource.
const resourceMatches = (rule: PolicyRule, resource: string, subresource?: string) => {
  const combined = subresource ? `${resource}/${subresource}` : resource;

  return (rule.resources ?? []).some(
    (candidate) => candidate === "*" || candidate === combined || (subresource !== undefined && candidate === `*/${subresource}`),
  );
};

const nameMatches = (rule: PolicyRule, name?: string) => {
  const names = rule.resourceNames ?? [];

  if (names.length === 0) return true;

  return name !== undefined && names.includes(name);
};

const pathMatches = (rule: PolicyRule, path: string) =>
  (rule.nonResourceURLs ?? []).some(
    (candidate) => candidate === "*" || candidate === path || (candidate.endsWith("*") && path.startsWith(candidate.slice(0, -1))),
  );

export const ruleCovers = (rule: PolicyRule, request: AccessRequest) => {
  if (!verbMatches(rule, request.verb)) return false;

  if (request.type === "nonResource") return pathMatches(rule, request.path);

  return groupMatches(rule, request.apiGroup) && resourceMatches(rule, request.resource, request.subresource) && nameMatches(rule, request.name);
};

const grantAppliesTo = (grant: Grant, request: AccessRequest) => {
  if (grant.scope.type === "cluster") return true;

  // A RoleBinding grants nothing outside its own namespace, and no non-resource URL at all.
  return request.type === "resource" && request.namespace === grant.scope.namespace;
};

export interface Authorization {
  readonly allowed: boolean;
  readonly matches: readonly { readonly grant: Grant; readonly rule: PolicyRule }[];
}

export const authorize = (grants: readonly Grant[], request: AccessRequest): Authorization => {
  const matches = grants.flatMap((grant) =>
    grantAppliesTo(grant, request) ? grant.rules.filter((rule) => ruleCovers(rule, request)).map((rule) => ({ grant, rule })) : [],
  );

  return { allowed: matches.length > 0, matches };
};

/** The namespaces a request is allowed in, or "all" when some cluster-wide grant covers it. */
export const namespacesAllowed = (grants: readonly Grant[], request: Omit<Extract<AccessRequest, { type: "resource" }>, "namespace" | "type">) => {
  const covering = grants.filter((grant) => grant.rules.some((rule) => ruleCovers(rule, { ...request, type: "resource" })));

  if (covering.some((grant) => grant.scope.type === "cluster")) return "all" as const;

  return [...new Set(covering.flatMap((grant) => (grant.scope.type === "namespace" ? [grant.scope.namespace] : [])))].sort();
};

// ---------------------------------------------------------------------------------------------
// The resources a matrix lists, and how a user's typed resource is read
// ---------------------------------------------------------------------------------------------

export interface KnownResource {
  readonly group: string;
  readonly resource: string;
  readonly subresource?: string;
  readonly namespaced: boolean;
}

const known = (group: string, resource: string, namespaced = true): KnownResource => {
  const [base, subresource] = resource.split("/");

  return { group, resource: base!, subresource, namespaced };
};

/** What a permission matrix lists by default: the resources an attacker or an auditor asks about first. */
export const commonResources: readonly KnownResource[] = [
  known("", "pods"),
  known("", "pods/exec"),
  known("", "pods/attach"),
  known("", "pods/portforward"),
  known("", "pods/log"),
  known("", "pods/ephemeralcontainers"),
  known("", "secrets"),
  known("", "configmaps"),
  known("", "services"),
  known("", "endpoints"),
  known("", "serviceaccounts"),
  known("", "serviceaccounts/token"),
  known("", "persistentvolumeclaims"),
  known("", "events"),
  known("", "namespaces", false),
  known("", "nodes", false),
  known("", "nodes/proxy", false),
  known("", "persistentvolumes", false),
  known("apps", "deployments"),
  known("apps", "daemonsets"),
  known("apps", "statefulsets"),
  known("apps", "replicasets"),
  known("batch", "jobs"),
  known("batch", "cronjobs"),
  known("networking.k8s.io", "networkpolicies"),
  known("networking.k8s.io", "ingresses"),
  known("rbac.authorization.k8s.io", "roles"),
  known("rbac.authorization.k8s.io", "rolebindings"),
  known("rbac.authorization.k8s.io", "clusterroles", false),
  known("rbac.authorization.k8s.io", "clusterrolebindings", false),
  known("admissionregistration.k8s.io", "mutatingwebhookconfigurations", false),
  known("admissionregistration.k8s.io", "validatingwebhookconfigurations", false),
  known("apiextensions.k8s.io", "customresourcedefinitions", false),
  known("certificates.k8s.io", "certificatesigningrequests", false),
  known("certificates.k8s.io", "certificatesigningrequests/approval", false),
  known("coordination.k8s.io", "leases"),
];

export const resourceLabel = (resource: { group: string; resource: string; subresource?: string }) =>
  `${resource.subresource ? `${resource.resource}/${resource.subresource}` : resource.resource}${resource.group ? `.${resource.group}` : ""}`;

const wellKnownGroupOf = new Map(commonResources.map((entry) => [entry.resource, entry.group]));

/**
 * Reads `pods`, `pods/log`, `deployments.apps`, `apps/deployments` or `cronjobs.batch/status` as
 * a group, a resource and a subresource.
 */
export const parseResource = (text: string): { group: string; resource: string; subresource?: string } | undefined => {
  const trimmed = text.trim().toLowerCase();

  if (!trimmed) return undefined;

  const groupSlash = /^([a-z0-9.-]+\.[a-z0-9.-]+|apps|batch|policy|autoscaling)\/([a-z0-9-]+)(?:\/([a-z0-9-]+))?$/.exec(trimmed);

  if (groupSlash) return { group: groupSlash[1]!, resource: groupSlash[2]!, subresource: groupSlash[3] };

  const [head, subresource] = trimmed.split("/");
  const dot = head!.indexOf(".");
  const resource = dot === -1 ? head! : head!.slice(0, dot);
  const group = dot === -1 ? (wellKnownGroupOf.get(resource) ?? "") : head!.slice(dot + 1);

  return { group, resource, subresource };
};

/** The verbs a matrix shows, in the order kubectl's own tooling lists them. */
export const matrixVerbs = ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"] as const;

/** Every resource named by a rule the principal holds, so the matrix shows custom resources too. */
export const resourcesNamedBy = (grants: readonly Grant[]): KnownResource[] => {
  const seen = new Map<string, KnownResource>();

  for (const grant of grants) {
    for (const rule of grant.rules) {
      for (const group of rule.apiGroups ?? []) {
        for (const resource of rule.resources ?? []) {
          if (group === "*" || resource === "*" || resource.startsWith("*/")) continue;

          const entry = known(group, resource);

          seen.set(resourceLabel(entry), entry);
        }
      }
    }
  }

  return [...seen.values()];
};

// ---------------------------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low";

export const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export interface RiskFinding {
  readonly id: string;
  readonly severity: Severity;
  readonly title: string;
  readonly detail: string;
  readonly where: "all" | readonly string[];
  readonly grants: readonly Grant[];
}

interface RiskCheck {
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  /** Severity when held cluster-wide, and when held only in some namespaces. */
  readonly severity: readonly [cluster: Severity, namespaced: Severity];
  readonly requests: readonly Omit<Extract<AccessRequest, { type: "resource" }>, "type" | "namespace">[];
  /** Cluster-scoped resources can only be granted cluster-wide. */
  readonly clusterOnly?: boolean;
}

const checks: readonly RiskCheck[] = [
  {
    id: "full-admin",
    title: "Full control (wildcard on everything)",
    detail: "Every verb on every resource of every API group, the same as cluster-admin where it applies.",
    severity: ["critical", "high"],
    requests: [{ verb: "*", apiGroup: "*", resource: "*" }],
  },
  {
    id: "rbac-escalate",
    title: "Can escalate or bind roles",
    detail: "The escalate and bind verbs let a subject grant permissions it does not itself hold.",
    severity: ["critical", "high"],
    requests: [
      { verb: "escalate", apiGroup: "rbac.authorization.k8s.io", resource: "clusterroles" },
      { verb: "bind", apiGroup: "rbac.authorization.k8s.io", resource: "clusterroles" },
      { verb: "escalate", apiGroup: "rbac.authorization.k8s.io", resource: "roles" },
      { verb: "bind", apiGroup: "rbac.authorization.k8s.io", resource: "roles" },
    ],
  },
  {
    id: "rbac-write",
    title: "Can change RBAC bindings",
    detail: "Creating or editing role bindings lets a subject hand any role it can reference to anyone, itself included.",
    severity: ["critical", "high"],
    requests: [
      { verb: "create", apiGroup: "rbac.authorization.k8s.io", resource: "clusterrolebindings" },
      { verb: "update", apiGroup: "rbac.authorization.k8s.io", resource: "clusterrolebindings" },
      { verb: "patch", apiGroup: "rbac.authorization.k8s.io", resource: "clusterrolebindings" },
      { verb: "create", apiGroup: "rbac.authorization.k8s.io", resource: "rolebindings" },
      { verb: "update", apiGroup: "rbac.authorization.k8s.io", resource: "rolebindings" },
      { verb: "patch", apiGroup: "rbac.authorization.k8s.io", resource: "rolebindings" },
    ],
  },
  {
    id: "impersonate",
    title: "Can impersonate other identities",
    detail: "Impersonating a user, group or service account acts with all of its permissions.",
    severity: ["critical", "critical"],
    clusterOnly: true,
    requests: [
      { verb: "impersonate", apiGroup: "", resource: "users" },
      { verb: "impersonate", apiGroup: "", resource: "groups" },
      { verb: "impersonate", apiGroup: "", resource: "serviceaccounts" },
    ],
  },
  {
    id: "webhooks",
    title: "Can change admission webhooks",
    detail: "A mutating or validating webhook sees, and may alter or block, every request it registers for.",
    severity: ["critical", "critical"],
    clusterOnly: true,
    requests: [
      { verb: "create", apiGroup: "admissionregistration.k8s.io", resource: "mutatingwebhookconfigurations" },
      { verb: "patch", apiGroup: "admissionregistration.k8s.io", resource: "mutatingwebhookconfigurations" },
      { verb: "create", apiGroup: "admissionregistration.k8s.io", resource: "validatingwebhookconfigurations" },
      { verb: "patch", apiGroup: "admissionregistration.k8s.io", resource: "validatingwebhookconfigurations" },
    ],
  },
  {
    id: "nodes-proxy",
    title: "Can reach the kubelet API through nodes/proxy",
    detail: "nodes/proxy reaches the kubelet directly, including exec into any pod on the node, bypassing admission.",
    severity: ["critical", "critical"],
    clusterOnly: true,
    requests: [{ verb: "get", apiGroup: "", resource: "nodes", subresource: "proxy" }],
  },
  {
    id: "secrets-read",
    title: "Can read secrets",
    detail: "Secrets hold credentials, including tokens of other service accounts, which may be more privileged.",
    severity: ["critical", "high"],
    requests: [
      { verb: "get", apiGroup: "", resource: "secrets" },
      { verb: "list", apiGroup: "", resource: "secrets" },
      { verb: "watch", apiGroup: "", resource: "secrets" },
    ],
  },
  {
    id: "token-create",
    title: "Can mint service account tokens",
    detail: "Creating serviceaccounts/token issues a token for another service account, and acts with its permissions.",
    severity: ["critical", "high"],
    requests: [{ verb: "create", apiGroup: "", resource: "serviceaccounts", subresource: "token" }],
  },
  {
    id: "pod-exec",
    title: "Can exec or attach into pods",
    detail: "A shell in a pod reads its mounted secrets and acts with its service account.",
    severity: ["high", "high"],
    requests: [
      { verb: "create", apiGroup: "", resource: "pods", subresource: "exec" },
      { verb: "get", apiGroup: "", resource: "pods", subresource: "exec" },
      { verb: "create", apiGroup: "", resource: "pods", subresource: "attach" },
    ],
  },
  {
    id: "workload-create",
    title: "Can create workloads",
    detail: "A new pod may run as any service account of its namespace and mount any of its secrets, unless admission policy stops it.",
    severity: ["high", "medium"],
    requests: [
      { verb: "create", apiGroup: "", resource: "pods" },
      { verb: "create", apiGroup: "apps", resource: "deployments" },
      { verb: "create", apiGroup: "apps", resource: "daemonsets" },
      { verb: "create", apiGroup: "apps", resource: "statefulsets" },
      { verb: "create", apiGroup: "batch", resource: "jobs" },
      { verb: "create", apiGroup: "batch", resource: "cronjobs" },
    ],
  },
  {
    id: "csr-approve",
    title: "Can approve certificate signing requests",
    detail: "Approving CSRs can issue client certificates for arbitrary identities.",
    severity: ["high", "high"],
    clusterOnly: true,
    requests: [{ verb: "update", apiGroup: "certificates.k8s.io", resource: "certificatesigningrequests", subresource: "approval" }],
  },
  {
    id: "pv-create",
    title: "Can create persistent volumes",
    detail: "A hostPath persistent volume mounts a node's filesystem into a pod.",
    severity: ["medium", "medium"],
    clusterOnly: true,
    requests: [{ verb: "create", apiGroup: "", resource: "persistentvolumes" }],
  },
  {
    id: "network-policy-write",
    title: "Can change network policies",
    detail: "Editing network policies can open traffic that isolation was meant to stop.",
    severity: ["medium", "low"],
    requests: [
      { verb: "create", apiGroup: "networking.k8s.io", resource: "networkpolicies" },
      { verb: "delete", apiGroup: "networking.k8s.io", resource: "networkpolicies" },
    ],
  },
  {
    id: "delete-broad",
    title: "Can delete workloads",
    detail: "Deleting deployments or pods is a direct availability risk.",
    severity: ["medium", "low"],
    requests: [
      { verb: "delete", apiGroup: "apps", resource: "deployments" },
      { verb: "deletecollection", apiGroup: "", resource: "pods" },
    ],
  },
];

/** Whether a rule holds the verb (or `*`) — used to tell a literal `*` check apart from any one verb. */
const ruleCoversLiteral = (rule: PolicyRule, request: Omit<Extract<AccessRequest, { type: "resource" }>, "type" | "namespace">) => {
  if (request.verb === "*" || request.apiGroup === "*" || request.resource === "*") {
    return (
      (request.verb !== "*" || rule.verbs.includes("*")) &&
      (request.apiGroup !== "*" || (rule.apiGroups ?? []).includes("*")) &&
      (request.resource !== "*" || (rule.resources ?? []).includes("*")) &&
      (rule.resourceNames ?? []).length === 0
    );
  }

  return ruleCovers(rule, { ...request, type: "resource" }) && (rule.resourceNames ?? []).length === 0;
};

export const risksOf = (grants: readonly Grant[]): RiskFinding[] => {
  const findings: RiskFinding[] = [];

  for (const check of checks) {
    const covering = grants.filter(
      (grant) =>
        (!check.clusterOnly || grant.scope.type === "cluster") &&
        grant.rules.some((rule) => check.requests.some((request) => ruleCoversLiteral(rule, request))),
    );

    if (covering.length === 0) continue;

    const clusterWide = covering.some((grant) => grant.scope.type === "cluster");
    const namespaces = [...new Set(covering.flatMap((grant) => (grant.scope.type === "namespace" ? [grant.scope.namespace] : [])))].sort();

    findings.push({
      id: check.id,
      severity: clusterWide ? check.severity[0] : check.severity[1],
      title: check.title,
      detail: check.detail,
      where: clusterWide ? "all" : namespaces,
      grants: covering,
    });
  }

  // Wildcards are a smell of their own, when they are not already the full-admin finding.
  if (!findings.some((finding) => finding.id === "full-admin")) {
    const wildcard = grants.filter((grant) =>
      grant.rules.some((rule) => rule.verbs.includes("*") || (rule.resources ?? []).includes("*") || (rule.apiGroups ?? []).includes("*")),
    );

    if (wildcard.length > 0) {
      findings.push({
        id: "wildcards",
        severity: "medium",
        title: "Uses wildcards",
        detail: "A wildcard verb, resource or API group also grants whatever is added to the cluster later.",
        where: wildcard.some((grant) => grant.scope.type === "cluster")
          ? "all"
          : [...new Set(wildcard.flatMap((grant) => (grant.scope.type === "namespace" ? [grant.scope.namespace] : [])))].sort(),
        grants: wildcard,
      });
    }
  }

  return findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
};

/** One number to sort principals by: the worst finding dominates, the rest break ties. */
export const riskScore = (findings: readonly RiskFinding[]) =>
  findings.reduce((score, finding) => score + 10 ** severityRank[finding.severity], 0);

export const worstSeverity = (findings: readonly RiskFinding[]): Severity | undefined => findings[0]?.severity;

/** Grants that come only from groups every service account is in, so that they do not drown out what is specific. */
export const isImplicitGroupGrant = (grant: Grant) =>
  grant.via === "group system:authenticated" || grant.via === "group system:serviceaccounts";

/** A compact `verbs on resources` text for one rule. */
export const describeRule = (rule: PolicyRule): string => {
  const verbs = rule.verbs.join(", ");

  if ((rule.nonResourceURLs ?? []).length > 0) return `${verbs} on ${rule.nonResourceURLs!.join(", ")}`;

  const groups = (rule.apiGroups ?? []).map((group) => (group === "" ? "core" : group));
  const resources = (rule.resources ?? []).join(", ");
  const names = (rule.resourceNames ?? []).length > 0 ? ` named ${rule.resourceNames!.join(", ")}` : "";

  return `${verbs} on ${resources}${names} (${groups.join(", ")})`;
};
