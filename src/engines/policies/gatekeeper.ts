/**
 * OPA Gatekeeper: ConstraintTemplates say what a kind of constraint checks, in Rego or CEL;
 * each constraint of that kind says where it applies, with which parameters, and what happens to
 * a resource that violates it.
 */

import { describeSelector, matchesSelector } from "../labels";
import {
  type MatchOutcome,
  type NormalizedPolicy,
  type PolicyEffect,
  type PolicyRef,
  policyRefKey,
  type PolicyResult,
  type Requirement,
  type SimulationTarget,
} from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any -- templates and constraints are open-ended JSON */
type Json = any;

const asArray = <T>(value: T[] | T | undefined | null): T[] => (Array.isArray(value) ? value : value == null ? [] : [value]);

/** The kind of constraint a template declares, which is the kind its constraints are served as. */
export const constraintKindOf = (template: Json): string | undefined => template?.spec?.crd?.spec?.names?.kind;

export interface TemplateSummary {
  readonly name: string;
  readonly constraintKind: string;
  readonly title?: string;
  readonly description?: string;
  readonly rego?: string;
  readonly libs: readonly string[];
  readonly cel: readonly { readonly expression: string; readonly message?: string }[];
  readonly parametersSchema?: unknown;
  readonly errors: readonly string[];
  readonly created: boolean;
}

export const summarizeTemplate = (template: Json): TemplateSummary | undefined => {
  const constraintKind = constraintKindOf(template);

  if (!constraintKind) return undefined;

  const annotations = template.metadata?.annotations ?? {};
  const targets = asArray<Json>(template.spec?.targets);
  const regoFromCode = targets.flatMap((target) => asArray<Json>(target.code).filter((entry) => entry.engine === "Rego").map((entry) => entry.source?.rego));
  const cel = targets.flatMap((target) =>
    asArray<Json>(target.code)
      .filter((entry) => entry.engine === "K8sNativeValidation")
      .flatMap((entry) => asArray<Json>(entry.source?.validations).map((validation) => ({ expression: validation.expression, message: validation.message }))),
  );

  return {
    name: template.metadata.name,
    constraintKind,
    title: annotations["metadata.gatekeeper.sh/title"],
    description: annotations.description,
    rego: targets.map((target) => target.rego).find(Boolean) ?? regoFromCode.find(Boolean),
    libs: targets.flatMap((target) => asArray<string>(target.libs)),
    cel,
    parametersSchema: template.spec?.crd?.spec?.validation?.openAPIV3Schema,
    errors: asArray<Json>(template.status?.byPod).flatMap((pod) => asArray<Json>(pod.errors).map((error) => error.message ?? String(error))),
    created: template.status?.created !== false,
  };
};

// Gatekeeper's namespace globs take a `*` only at the start or the end: `kube-*`, `*-system`.
const namespaceGlobMatches = (pattern: string, namespace: string) => {
  if (pattern.endsWith("*")) return namespace.startsWith(pattern.slice(0, -1));
  if (pattern.startsWith("*")) return namespace.endsWith(pattern.slice(1));

  return pattern === namespace;
};

const effectOfAction = (action: unknown): PolicyEffect => {
  switch (String(action ?? "deny").toLowerCase()) {
    case "dryrun":
      return "audit";
    case "warn":
      return "warn";
    default:
      return "enforce";
  }
};

/** The effect at admission. `scoped` constraints name it per enforcement point. */
const admissionEffectOf = (spec: Json): PolicyEffect => {
  if (String(spec?.enforcementAction ?? "deny").toLowerCase() !== "scoped") return effectOfAction(spec?.enforcementAction);

  const scoped = asArray<Json>(spec.scopedEnforcementActions).find((entry) =>
    asArray<Json>(entry.enforcementPoints).some((point) => point.name === "validation.gatekeeper.sh" || point.name === "*"),
  );

  return scoped ? effectOfAction(scoped.action) : "audit";
};

const describeKinds = (match: Json) => {
  const kinds = asArray<Json>(match?.kinds);

  if (kinds.length === 0) return "any kind";

  return kinds
    .map((entry) => {
      const groups = asArray<string>(entry.apiGroups).map((group) => (group === "" ? "core" : group));

      return `${asArray(entry.kinds).join(", ") || "any kind"}${groups.length > 0 && !groups.includes("*") ? ` (${groups.join(", ")})` : ""}`;
    })
    .join("; ");
};

export const describeConstraintMatch = (match: Json): string[] => {
  const lines = [`Applies to ${describeKinds(match)}`];

  if (match?.scope && match.scope !== "*") lines.push(`Only ${match.scope === "Cluster" ? "cluster-scoped" : "namespaced"} resources`);
  if (match?.name) lines.push(`Only resources named ${match.name}`);
  if (asArray(match?.namespaces).length > 0) lines.push(`In namespaces ${asArray(match.namespaces).join(", ")}`);
  if (asArray(match?.excludedNamespaces).length > 0) lines.push(`Except namespaces ${asArray(match.excludedNamespaces).join(", ")}`);
  if (match?.labelSelector) lines.push(`Labelled ${describeSelector(match.labelSelector, "anything")}`);
  if (match?.namespaceSelector) lines.push(`In namespaces labelled ${describeSelector(match.namespaceSelector, "anything")}`);

  return lines;
};

export const evaluateConstraintMatch = (match: Json, target: SimulationTarget): MatchOutcome => {
  const kinds = asArray<Json>(match?.kinds);
  const reasons: string[] = [];

  if (kinds.length > 0) {
    const hit = kinds.some((entry) => {
      const groups = asArray<string>(entry.apiGroups);
      const names = asArray<string>(entry.kinds);

      return (groups.length === 0 || groups.includes("*") || groups.includes(target.group)) && (names.length === 0 || names.includes("*") || names.includes(target.kind));
    });

    if (!hit) return { applies: false, reason: `kind ${target.kind} is not among ${describeKinds(match)}` };

    reasons.push(`kind among ${describeKinds(match)}`);
  }

  if (match?.scope === "Cluster" && target.namespace !== undefined) return { applies: false, reason: "it only covers cluster-scoped resources" };
  if (match?.scope === "Namespaced" && target.namespace === undefined) return { applies: false, reason: "it only covers namespaced resources" };

  const caveats: string[] = [];

  if (match?.name) {
    if (target.name === undefined) caveats.push(`only resources named ${match.name}`);
    else if (!namespaceGlobMatches(match.name, target.name)) return { applies: false, reason: `name is not ${match.name}` };
  }

  const namespaces = asArray<string>(match?.namespaces);
  const excluded = asArray<string>(match?.excludedNamespaces);

  // A cluster-scoped resource is not filtered by namespaces at all, by Gatekeeper's rules.
  if (target.namespace !== undefined) {
    if (namespaces.length > 0 && !namespaces.some((pattern) => namespaceGlobMatches(pattern, target.namespace!))) {
      return { applies: false, reason: `namespace ${target.namespace} is not among ${namespaces.join(", ")}` };
    }

    const exclusion = excluded.find((pattern) => namespaceGlobMatches(pattern, target.namespace!));

    if (exclusion) return { applies: false, reason: `namespace ${target.namespace} is excluded (${exclusion})` };

    if (match?.namespaceSelector && !matchesSelector(match.namespaceSelector, target.namespaceLabels)) {
      return { applies: false, reason: `namespace labels do not match ${describeSelector(match.namespaceSelector)}` };
    }
  }

  if (match?.labelSelector && !matchesSelector(match.labelSelector, target.labels)) {
    return { applies: false, reason: `labels do not match ${describeSelector(match.labelSelector)}` };
  }

  return { applies: true, reasons, caveats };
};

const describeParameters = (parameters: Json): Requirement[] => {
  if (!parameters || typeof parameters !== "object" || Object.keys(parameters).length === 0) return [];

  return [
    {
      text: "With parameters",
      code: Object.entries(parameters as Record<string, unknown>)
        .map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
        .join("\n"),
      codeLanguage: "yaml",
    },
  ];
};

/** A constraint, read together with the template that defines its kind. */
export const normalizeConstraint = (constraint: Json, template: TemplateSummary | undefined): NormalizedPolicy => {
  const ref: PolicyRef = { engine: "gatekeeper", kind: constraint.kind, name: constraint.metadata.name };
  const spec = constraint.spec ?? {};
  const effect = admissionEffectOf(spec);
  const notes: string[] = [];

  if (!template) notes.push(`No ConstraintTemplate defines ${constraint.kind}: the constraint does nothing until one does.`);
  if (template && template.errors.length > 0) notes.push(`The template reports errors: ${template.errors.join("; ")}`);
  if (String(spec.enforcementAction ?? "").toLowerCase() === "scoped") notes.push("Enforcement is scoped per enforcement point; shown is the effect at admission.");

  const requirements: Requirement[] = [
    { text: template?.description ?? template?.title ?? `Checks of ${constraint.kind}` },
    ...describeParameters(spec.parameters),
    ...(template?.cel ?? []).map((validation) => ({ text: validation.message ?? "Must satisfy", code: validation.expression, codeLanguage: "cel" as const })),
    ...(template?.rego ? [{ text: "Violations are what this Rego reports", code: template.rego, codeLanguage: "rego" as const }] : []),
  ];

  const status = constraint.status ?? {};

  return {
    ref,
    title: constraint.metadata.name,
    description: template?.description,
    ready: status.byPod ? { ok: asArray<Json>(status.byPod).every((pod) => pod.enforced !== false && asArray(pod.errors).length === 0) } : undefined,
    reportedViolations: typeof status.totalViolations === "number" ? status.totalViolations : undefined,
    notes,
    raw: constraint,
    rules: [
      {
        id: `${policyRefKey(ref)}#constraint`,
        policy: ref,
        name: constraint.kind,
        type: template?.cel.length ? "cel" : "rego",
        effect,
        effectIn: () => effect,
        scope: describeConstraintMatch(spec.match),
        requirements,
        conditions: [],
        matches: (target) => evaluateConstraintMatch(spec.match, target),
      },
    ],
  };
};

/** What a constraint's last audit found, which Gatekeeper keeps in its status. */
export const constraintViolations = (constraint: Json): PolicyResult[] =>
  asArray<Json>(constraint.status?.violations).map((violation) => ({
    engine: "gatekeeper",
    policy: constraint.metadata.name,
    rule: constraint.kind,
    result: String(violation.enforcementAction ?? "deny").toLowerCase() === "warn" ? "warn" : "fail",
    message: violation.message,
    resource: { kind: violation.kind, apiVersion: violation.version, namespace: violation.namespace, name: violation.name },
    timestamp: constraint.status?.auditTimestamp ? Date.parse(constraint.status.auditTimestamp) : undefined,
  }));

/** Namespaces the Gatekeeper Config keeps out of admission: `webhook` or every process. */
export const admissionExcludedNamespaces = (configs: readonly Json[]): string[] =>
  configs.flatMap((config) =>
    asArray<Json>(config.spec?.match)
      .filter((entry) => asArray<string>(entry.processes).some((process) => process === "*" || process === "webhook"))
      .flatMap((entry) => asArray<string>(entry.excludedNamespaces)),
  );

export const namespaceIsExcludedByConfig = (excluded: readonly string[], namespace: string | undefined) =>
  namespace !== undefined ? excluded.find((pattern) => namespaceGlobMatches(pattern, namespace)) : undefined;
