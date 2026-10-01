import { getInjectable2 } from "@k8slens/injectable";
import { computed } from "mobx";
import { clusterKindInjectable, readKinds } from "../data/cluster-kind.injectable";
import { constraintWatchKey } from "../data/watch-specs";
import { parseLabels } from "../engines/labels";
import {
  admissionExcludedNamespaces,
  constraintKindOf,
  constraintViolations,
  normalizeConstraint,
  summarizeTemplate,
  type TemplateSummary,
} from "../engines/policies/gatekeeper";
import {
  type NormalizedException,
  normalizeKyvernoCelException,
  normalizeKyvernoCelPolicy,
  normalizeKyvernoException,
  normalizeKyvernoPolicy,
} from "../engines/policies/kyverno";
import { kindInfo, type NormalizedPolicy, type PolicyEngine, policyRefKey, type PolicyResult, simulationKinds } from "../engines/policies/model";
import { resultsOfReport, tally, type ResultTally } from "../engines/policies/reports";
import { simulate } from "../engines/policies/simulate";
import { type LabDocument, overlay as layOver } from "../engines/lab/manifests";
import type { RuleCheck } from "../engines/policies/check";
import type { ApplicableRule } from "../engines/policies/simulate";
import { labModelInjectable } from "../lab/lab-model.injectable";
import { policyStateInjectable } from "./policy-state.injectable";

/* eslint-disable @typescript-eslint/no-explicit-any -- policy resources are open-ended JSON */
type Json = any;

const keys = [
  "kyvernoClusterPolicies",
  "kyvernoPolicies",
  "kyvernoExceptions",
  "kyvernoValidatingPolicies",
  "kyvernoNamespacedValidatingPolicies",
  "kyvernoCelExceptions",
  "policyReports",
  "clusterPolicyReports",
  "openReports",
  "openClusterReports",
  "constraintTemplates",
  "gatekeeperConfigs",
  "namespaces",
] as const;

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

/** One engine failing to read one policy must not take the view down: the policy is shown as unreadable. */
const safely = <T>(read: () => T, onError: (message: string) => void): T | undefined => {
  try {
    return read();
  } catch (error) {
    onError(messageOf(error));

    return undefined;
  }
};

export interface PolicyEntry {
  readonly policy: NormalizedPolicy;
  readonly key: string;
  readonly results: ResultTally;
  /** Failing and warning results, newest first. */
  readonly findings: readonly PolicyResult[];
}

/** The admission policies of a cluster, what they require and of whom, as the policies view shows them. */
export const policyModelInjectable = getInjectable2({
  id: "real-governance-policy-model",

  instantiate: (di) => {
    const loadOf = di.inject(clusterKindInjectable);
    const stateOf = di.inject(policyStateInjectable);
    const labOf = di.inject(labModelInjectable);

    return (clusterId: string) => {
      const state = stateOf(clusterId);
      const lab = labOf(clusterId);
      const labOverlay = computed(() => lab.overlay.get());
      const cluster = computed(() => readKinds(loadOf, clusterId, keys));
      const withKind = (kind: string) => (resource: Json) => ({ kind, ...resource });

      // The cluster's policies with the lab's drafts laid over them: a draft replaces its namesake.
      const snapshot = computed(() => {
        const read = cluster.get();
        const drafts = labOverlay.get();

        if (!drafts.active) return read;

        const { items } = read;
        const kyverno = layOver(
          [...(items.kyvernoClusterPolicies as Json[]).map(withKind("ClusterPolicy")), ...(items.kyvernoPolicies as Json[]).map(withKind("Policy"))],
          drafts.kyvernoPolicies,
        );
        const cel = layOver(
          [
            ...(items.kyvernoValidatingPolicies as Json[]).map(withKind("ValidatingPolicy")),
            ...(items.kyvernoNamespacedValidatingPolicies as Json[]).map(withKind("NamespacedValidatingPolicy")),
          ],
          drafts.kyvernoCelPolicies,
        );

        return {
          ...read,
          items: {
            ...items,
            kyvernoClusterPolicies: kyverno.filter((policy) => policy.kind === "ClusterPolicy"),
            kyvernoPolicies: kyverno.filter((policy) => policy.kind === "Policy"),
            kyvernoValidatingPolicies: cel.filter((policy) => policy.kind === "ValidatingPolicy"),
            kyvernoNamespacedValidatingPolicies: cel.filter((policy) => policy.kind === "NamespacedValidatingPolicy"),
            kyvernoExceptions: layOver((items.kyvernoExceptions as Json[]).map(withKind("PolicyException")), drafts.kyvernoExceptions),
            kyvernoCelExceptions: layOver((items.kyvernoCelExceptions as Json[]).map(withKind("PolicyException")), drafts.kyvernoCelExceptions),
            constraintTemplates: layOver((items.constraintTemplates as Json[]).map(withKind("ConstraintTemplate")), drafts.constraintTemplates),
            namespaces: layOver((items.namespaces as Json[]).map(withKind("Namespace")), drafts.namespaces),
          },
        };
      });

      const templates = computed(() =>
        (snapshot.get().items.constraintTemplates as Json[]).map(summarizeTemplate).filter((template): template is TemplateSummary => Boolean(template)),
      );

      // Each template is a kind of constraint of its own, watched once the template is known.
      const constraints = computed(() => {
        const watchKeys = templates.get().map((template) => constraintWatchKey(template.constraintKind));
        const read = readKinds(loadOf, clusterId, watchKeys);
        const fromCluster = watchKeys.flatMap((key) => read.items[key] as Json[]);

        return { items: layOver(fromCluster, labOverlay.get().constraints), loading: read.loading, failures: read.failures };
      });

      const installed = computed(() => {
        const { absent, loading } = snapshot.get();

        return {
          settled: !loading,
          kyverno: !absent.has("kyvernoClusterPolicies"),
          kyvernoCel: !absent.has("kyvernoValidatingPolicies"),
          gatekeeper: !absent.has("constraintTemplates"),
          reports: !absent.has("policyReports") || !absent.has("openReports"),
        };
      });

      const readFailures = computed(() => {
        const failures: string[] = [];
        const { items } = snapshot.get();
        const templateByKind = new Map(templates.get().map((template) => [template.constraintKind, template]));
        const read = (resource: Json, normalize: (resource: Json) => NormalizedPolicy) =>
          safely(() => normalize(resource), (message) => failures.push(`${resource?.kind} ${resource?.metadata?.name}: ${message}`));

        const policies = [
          ...(items.kyvernoClusterPolicies as Json[]).map((resource) => read({ kind: "ClusterPolicy", ...resource }, normalizeKyvernoPolicy)),
          ...(items.kyvernoPolicies as Json[]).map((resource) => read({ kind: "Policy", ...resource }, normalizeKyvernoPolicy)),
          ...(items.kyvernoValidatingPolicies as Json[]).map((resource) => read({ kind: "ValidatingPolicy", ...resource }, normalizeKyvernoCelPolicy)),
          ...(items.kyvernoNamespacedValidatingPolicies as Json[]).map((resource) =>
            read({ kind: "NamespacedValidatingPolicy", ...resource }, normalizeKyvernoCelPolicy),
          ),
          ...constraints.get().items.map((resource) => read(resource, (constraint) => normalizeConstraint(constraint, templateByKind.get(constraint.kind)))),
        ].filter((policy): policy is NormalizedPolicy => Boolean(policy));

        return { policies, failures };
      });

      const policies = computed(() => readFailures.get().policies);

      const exceptions = computed((): NormalizedException[] => {
        const { items } = snapshot.get();

        return [
          ...(items.kyvernoExceptions as Json[]).map((resource) => safely(() => normalizeKyvernoException(resource), () => undefined)),
          ...(items.kyvernoCelExceptions as Json[]).map((resource) => safely(() => normalizeKyvernoCelException(resource), () => undefined)),
        ].filter((exception): exception is NormalizedException => Boolean(exception));
      });

      const results = computed((): PolicyResult[] => {
        const { items } = snapshot.get();

        return [
          ...[...items.policyReports, ...items.clusterPolicyReports, ...items.openReports, ...items.openClusterReports].flatMap((report) =>
            safely(() => resultsOfReport(report), () => undefined) ?? [],
          ),
          ...constraints.get().items.flatMap(constraintViolations),
        ];
      });

      // Results name their policy by name, and by namespace when it is namespaced.
      const entries = computed((): PolicyEntry[] => {
        const byPolicy = new Map<string, PolicyResult[]>();
        const keyOf = (engine: PolicyEngine | "any", name: string, namespace?: string) => `${engine}|${namespace ?? ""}|${name}`;

        for (const result of results.get()) {
          const key = result.engine === "gatekeeper" ? keyOf("gatekeeper", `${result.rule}/${result.policy}`) : keyOf("any", result.policy, result.policyNamespace);

          byPolicy.set(key, [...(byPolicy.get(key) ?? []), result]);
        }

        return policies.get().map((policy) => {
          const own =
            policy.ref.engine === "gatekeeper"
              ? (byPolicy.get(keyOf("gatekeeper", `${policy.ref.kind}/${policy.ref.name}`)) ?? [])
              : (byPolicy.get(keyOf("any", policy.ref.name, policy.ref.namespace)) ?? []);

          return {
            policy,
            key: policyRefKey(policy.ref),
            results: tally(own),
            findings: own.filter((result) => result.result !== "pass" && result.result !== "skip").sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0)),
          };
        });
      });

      const visibleEntries = computed(() => {
        const search = state.search.get().trim().toLowerCase();

        return entries
          .get()
          .filter(
            (entry) =>
              (state.engines.size === 0 || state.engines.has(entry.policy.ref.engine)) &&
              (state.effects.size === 0 || entry.policy.rules.some((rule) => state.effects.has(rule.effect))) &&
              (!search ||
                `${entry.policy.ref.name} ${entry.policy.title} ${entry.policy.ref.kind} ${entry.policy.category ?? ""}`.toLowerCase().includes(search)),
          )
          .sort(
            (a, b) =>
              b.results.fail - a.results.fail ||
              (b.policy.reportedViolations ?? 0) - (a.policy.reportedViolations ?? 0) ||
              a.policy.title.localeCompare(b.policy.title),
          );
      });

      const namespaces = computed(() => (snapshot.get().items.namespaces as Json[]).map((namespace) => namespace.metadata.name as string).sort());

      const namespaceLabels = computed(
        () => new Map((snapshot.get().items.namespaces as Json[]).map((namespace) => [namespace.metadata.name as string, (namespace.metadata.labels ?? {}) as Record<string, string>])),
      );

      const simulation = computed(() => {
        const form = state.simulation;
        const info = kindInfo(form.kind.trim() || "Pod");
        const namespace = info.namespaced ? form.namespace.trim() || "default" : undefined;
        const target = {
          kind: info.kind,
          group: info.group,
          resource: info.resource,
          namespace,
          namespaceLabels: namespace ? { "kubernetes.io/metadata.name": namespace, ...(namespaceLabels.get().get(namespace) ?? {}) } : {},
          name: form.name.trim() || undefined,
          labels: parseLabels(form.labels),
          operation: form.operation,
        };

        return {
          target,
          namespaceKnown: !namespace || namespaceLabels.get().has(namespace),
          ...simulate(
            {
              policies: policies.get(),
              exceptions: exceptions.get(),
              gatekeeperExcludedNamespaces: admissionExcludedNamespaces(snapshot.get().items.gatekeeperConfigs as Json[]),
            },
            target,
          ),
        };
      });

      const contextForSimulation = (only?: (policy: NormalizedPolicy) => boolean) => ({
        policies: only ? policies.get().filter(only) : policies.get(),
        exceptions: exceptions.get(),
        gatekeeperExcludedNamespaces: admissionExcludedNamespaces(snapshot.get().items.gatekeeperConfigs as Json[]),
      });

      /**
       * What admission would do with a manifest of the lab: which rules apply, and for each whether
       * the manifest complies, where the lab can tell.
       */
      const checkDocument = (document: LabDocument, operation: "CREATE" | "UPDATE" = "CREATE", only?: (policy: NormalizedPolicy) => boolean) => {
        const info = kindInfo(document.kind);
        const namespace = document.namespace;
        const target = {
          kind: document.kind,
          group: document.group,
          resource: info.resource,
          namespace,
          namespaceLabels: namespace ? { "kubernetes.io/metadata.name": namespace, ...(namespaceLabels.get().get(namespace) ?? {}) } : {},
          name: document.name,
          labels: (document.raw?.metadata?.labels ?? {}) as Record<string, string>,
          operation,
        };
        const simulation = simulate(contextForSimulation(only), target);
        const checked = simulation.applicable.map((entry): ApplicableRule & { check: RuleCheck } => ({
          ...entry,
          check: entry.rule.check
            ? entry.rule.check(document.raw, operation)
            : {
                status: "unknown",
                detail: entry.policy.ref.engine === "gatekeeper" ? "Rego is evaluated by Gatekeeper only." : "CEL is evaluated by Kyverno only.",
              },
        }));
        const enforced = checked.filter((entry) => entry.effect === "enforce");
        const verdict: "rejected" | "admitted" | "warned" | "reported" | "unsure" = enforced.some((entry) => entry.check.status === "fail")
          ? "rejected"
          : enforced.some((entry) => entry.check.status === "unknown")
            ? "unsure"
            : checked.some((entry) => entry.effect === "warn" && entry.check.status === "fail")
              ? "warned"
              : checked.some((entry) => entry.check.status === "fail")
                ? "reported"
                : "admitted";

        return { target, namespaceKnown: !namespace || namespaceLabels.get().has(namespace), checked, skipped: simulation.skipped, verdict };
      };

      const violations = computed(() => {
        const search = state.violationSearch.get().trim().toLowerCase();

        return results
          .get()
          .filter(
            (result) =>
              (result.result === "fail" || result.result === "warn" || result.result === "error") &&
              state.violationResults.has(result.result) &&
              (!search ||
                `${result.policy} ${result.rule ?? ""} ${result.resource.kind} ${result.resource.namespace ?? ""}/${result.resource.name} ${result.message ?? ""}`
                  .toLowerCase()
                  .includes(search)),
          )
          .sort((a, b) => (a.resource.namespace ?? "").localeCompare(b.resource.namespace ?? "") || a.resource.name.localeCompare(b.resource.name));
      });

      const totals = computed(() => {
        const all = entries.get();

        return {
          policies: all.length,
          enforcing: all.filter((entry) => entry.policy.rules.some((rule) => rule.effect === "enforce" && !rule.autogen)).length,
          failing: tally(results.get()).fail,
          warning: tally(results.get()).warn,
        };
      });

      return {
        clusterId,
        state,
        snapshot,
        lab,
        labOverlay,
        checkDocument,
        isDraftPolicy: (ref: { readonly kind: string; readonly namespace?: string; readonly name: string }) => lab.isDraft(ref.kind, ref.namespace, ref.name),
        installed,
        constraints,
        templates,
        entries,
        visibleEntries,
        readFailures: computed(() => readFailures.get().failures),
        exceptions,
        namespaces,
        simulation,
        simulationKinds,
        violations,
        totals,
        policyKeyOf: (engine: PolicyEngine, name: string, namespace?: string) =>
          entries.get().find((entry) => entry.policy.ref.name === name && (engine === "gatekeeper" ? entry.policy.ref.engine === "gatekeeper" : entry.policy.ref.engine !== "gatekeeper") && (entry.policy.ref.namespace ?? undefined) === namespace)?.key,
      };
    };
  },
});

export type PolicyModel = ReturnType<ReturnType<(typeof policyModelInjectable)["instantiate"]>>;
