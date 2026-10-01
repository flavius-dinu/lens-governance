/** Everything the views read, by a key each view and loader agree on. */

import {
  clusterRoleBindingKind,
  clusterRoleKind,
  coreV1,
  type KubeResourceKind,
  type KubernetesApiVersion,
  namespaceKind,
  networkingV1,
  networkPolicyKind,
  podKind,
  rbacAuthorizationV1,
  roleBindingKind,
  roleKind,
  serviceAccountKind,
  serviceKind,
} from "@k8slens/kubernetes-contracts";
import {
  calicoCrdV1,
  calicoGlobalNetworkPolicyKind,
  calicoNetworkPolicyKind,
  calicoTierKind,
  ciliumClusterwideNetworkPolicyKind,
  ciliumNetworkPolicyKind,
  ciliumV2,
  clusterPolicyReportKind,
  constraintKindNamed,
  constraintTemplateKind,
  gatekeeperConfigKind,
  gatekeeperConfigV1alpha1,
  gatekeeperConstraintsV1beta1,
  gatekeeperTemplatesV1,
  kyvernoCelExceptionKind,
  kyvernoClusterPolicyKind,
  kyvernoExceptionKind,
  kyvernoNamespacedValidatingPolicyKind,
  kyvernoPoliciesV1,
  kyvernoPolicyKind,
  kyvernoV1,
  kyvernoV2,
  kyvernoValidatingPolicyKind,
  openClusterReportKind,
  openReportKind,
  openReportsV1alpha1,
  policyReportKind,
  wgPolicyV1alpha2,
} from "./kinds";

export interface WatchSpec {
  readonly key: string;
  /** What the user is told could not be read. */
  readonly label: string;
  readonly kind: KubeResourceKind;
  readonly apiVersion: KubernetesApiVersion;
  /** A custom resource: asked whether it is served first, so that a missing operator is not an error. */
  readonly optional: boolean;
}

const spec = (key: string, label: string, kind: KubeResourceKind, apiVersion: KubernetesApiVersion, optional = false): WatchSpec => ({
  key,
  label,
  kind,
  apiVersion,
  optional,
});

const fixed = [
  spec("pods", "Pods", podKind, coreV1),
  spec("namespaces", "Namespaces", namespaceKind, coreV1),
  spec("services", "Services", serviceKind, coreV1),
  spec("serviceAccounts", "Service accounts", serviceAccountKind, coreV1),
  spec("roles", "Roles", roleKind, rbacAuthorizationV1),
  spec("clusterRoles", "Cluster roles", clusterRoleKind, rbacAuthorizationV1),
  spec("roleBindings", "Role bindings", roleBindingKind, rbacAuthorizationV1),
  spec("clusterRoleBindings", "Cluster role bindings", clusterRoleBindingKind, rbacAuthorizationV1),
  spec("networkPolicies", "Network policies", networkPolicyKind, networkingV1),

  spec("kyvernoClusterPolicies", "Kyverno cluster policies", kyvernoClusterPolicyKind, kyvernoV1, true),
  spec("kyvernoPolicies", "Kyverno policies", kyvernoPolicyKind, kyvernoV1, true),
  spec("kyvernoExceptions", "Kyverno policy exceptions", kyvernoExceptionKind, kyvernoV2, true),
  spec("kyvernoValidatingPolicies", "Kyverno validating policies", kyvernoValidatingPolicyKind, kyvernoPoliciesV1, true),
  spec("kyvernoNamespacedValidatingPolicies", "Kyverno namespaced validating policies", kyvernoNamespacedValidatingPolicyKind, kyvernoPoliciesV1, true),
  spec("kyvernoCelExceptions", "Kyverno CEL policy exceptions", kyvernoCelExceptionKind, kyvernoPoliciesV1, true),
  spec("policyReports", "Policy reports", policyReportKind, wgPolicyV1alpha2, true),
  spec("clusterPolicyReports", "Cluster policy reports", clusterPolicyReportKind, wgPolicyV1alpha2, true),
  spec("openReports", "Reports (openreports.io)", openReportKind, openReportsV1alpha1, true),
  spec("openClusterReports", "Cluster reports (openreports.io)", openClusterReportKind, openReportsV1alpha1, true),
  spec("constraintTemplates", "Gatekeeper constraint templates", constraintTemplateKind, gatekeeperTemplatesV1, true),
  spec("gatekeeperConfigs", "Gatekeeper config", gatekeeperConfigKind, gatekeeperConfigV1alpha1, true),

  spec("ciliumPolicies", "Cilium network policies", ciliumNetworkPolicyKind, ciliumV2, true),
  spec("ciliumClusterwidePolicies", "Cilium clusterwide network policies", ciliumClusterwideNetworkPolicyKind, ciliumV2, true),
  spec("calicoPolicies", "Calico network policies", calicoNetworkPolicyKind, calicoCrdV1, true),
  spec("calicoGlobalPolicies", "Calico global network policies", calicoGlobalNetworkPolicyKind, calicoCrdV1, true),
  spec("calicoTiers", "Calico tiers", calicoTierKind, calicoCrdV1, true),
] as const;

export type FixedWatchKey = (typeof fixed)[number]["key"];

const specs = new Map<string, WatchSpec>(fixed.map((entry) => [entry.key, entry]));

/** The key of the constraints of one Gatekeeper template, declared the first time it is asked for. */
export const constraintWatchKey = (constraintKind: string) => {
  const key = `constraint:${constraintKind}`;

  if (!specs.has(key)) specs.set(key, spec(key, `${constraintKind} constraints`, constraintKindNamed(constraintKind), gatekeeperConstraintsV1beta1, true));

  return key;
};

export const watchSpecOf = (key: string): WatchSpec => {
  const found = specs.get(key);

  if (!found) throw new Error(`real-governance: nothing is declared to watch as "${key}"`);

  return found;
};
