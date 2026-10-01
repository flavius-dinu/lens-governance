/** The custom resource kinds this extension reads, besides the built-in ones Lens declares. */

import { getKubeResourceKind, getKubernetesApiVersion } from "@k8slens/kubernetes-contracts";

/** Policies are read as open-ended JSON: the engines take them apart defensively. */
interface OpenShape {
  spec?: unknown;
  status?: unknown;
}

const kind = <V extends string>(_version: V, name: string) => getKubeResourceKind<Record<V, OpenShape>>(name);

export const kyvernoV1 = getKubernetesApiVersion("kyverno.io/v1");
export const kyvernoV2 = getKubernetesApiVersion("kyverno.io/v2");
export const kyvernoPoliciesV1 = getKubernetesApiVersion("policies.kyverno.io/v1");
export const wgPolicyV1alpha2 = getKubernetesApiVersion("wgpolicyk8s.io/v1alpha2");
export const openReportsV1alpha1 = getKubernetesApiVersion("openreports.io/v1alpha1");
export const gatekeeperTemplatesV1 = getKubernetesApiVersion("templates.gatekeeper.sh/v1");
export const gatekeeperConstraintsV1beta1 = getKubernetesApiVersion("constraints.gatekeeper.sh/v1beta1");
export const gatekeeperConfigV1alpha1 = getKubernetesApiVersion("config.gatekeeper.sh/v1alpha1");
export const ciliumV2 = getKubernetesApiVersion("cilium.io/v2");
export const calicoCrdV1 = getKubernetesApiVersion("crd.projectcalico.org/v1");

export const kyvernoClusterPolicyKind = kind("kyverno.io/v1", "ClusterPolicy");
export const kyvernoPolicyKind = kind("kyverno.io/v1", "Policy");
export const kyvernoExceptionKind = kind("kyverno.io/v2", "PolicyException");
export const kyvernoValidatingPolicyKind = kind("policies.kyverno.io/v1", "ValidatingPolicy");
export const kyvernoNamespacedValidatingPolicyKind = kind("policies.kyverno.io/v1", "NamespacedValidatingPolicy");
export const kyvernoCelExceptionKind = kind("policies.kyverno.io/v1", "PolicyException");
export const policyReportKind = kind("wgpolicyk8s.io/v1alpha2", "PolicyReport");
export const clusterPolicyReportKind = kind("wgpolicyk8s.io/v1alpha2", "ClusterPolicyReport");
export const openReportKind = kind("openreports.io/v1alpha1", "Report");
export const openClusterReportKind = kind("openreports.io/v1alpha1", "ClusterReport");
export const constraintTemplateKind = kind("templates.gatekeeper.sh/v1", "ConstraintTemplate");
export const gatekeeperConfigKind = kind("config.gatekeeper.sh/v1alpha1", "Config");
export const ciliumNetworkPolicyKind = kind("cilium.io/v2", "CiliumNetworkPolicy");
export const ciliumClusterwideNetworkPolicyKind = kind("cilium.io/v2", "CiliumClusterwideNetworkPolicy");
export const calicoNetworkPolicyKind = kind("crd.projectcalico.org/v1", "NetworkPolicy");
export const calicoGlobalNetworkPolicyKind = kind("crd.projectcalico.org/v1", "GlobalNetworkPolicy");
export const calicoTierKind = kind("crd.projectcalico.org/v1", "Tier");

/** A Gatekeeper constraint's kind is only known once its template is: one per template, declared as needed. */
export const constraintKindNamed = (name: string) => kind("constraints.gatekeeper.sh/v1beta1", name);
