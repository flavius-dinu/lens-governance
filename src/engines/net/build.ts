/** Assembling the network model of a cluster, and telling which CNI enforces its policies. */

import { type CalicoTier, normalizeCalicoPolicy, toCalicoTier } from "./calico";
import { normalizeCiliumPolicy } from "./cilium";
import type { EnforcementMode, NetworkModel } from "./evaluate";
import { normalizeKubernetesNetworkPolicy } from "./kubernetes";
import type { ClusterContext, PodInfo } from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any -- raw resources from the cluster */
type Json = any;

export interface CniDetection {
  readonly mode: EnforcementMode;
  /** The CNI recognised by its agent pods, if any. */
  readonly cni?: string;
  readonly enforcesNetworkPolicy: boolean | "unknown";
  readonly notes: readonly string[];
}

const agents: readonly { readonly cni: string; readonly enforces: boolean; readonly matches: (pod: PodInfo) => boolean }[] = [
  { cni: "Cilium", enforces: true, matches: (pod) => pod.labels["k8s-app"] === "cilium" || pod.labels["app.kubernetes.io/name"] === "cilium-agent" },
  { cni: "Calico", enforces: true, matches: (pod) => pod.labels["k8s-app"] === "calico-node" || pod.labels["app.kubernetes.io/name"] === "calico-node" },
  { cni: "Antrea", enforces: true, matches: (pod) => pod.labels.app === "antrea" && pod.labels.component === "antrea-agent" },
  { cni: "kube-router", enforces: true, matches: (pod) => pod.labels["k8s-app"] === "kube-router" },
  { cni: "Weave Net", enforces: true, matches: (pod) => pod.labels.name === "weave-net" },
  { cni: "kindnet", enforces: true, matches: (pod) => pod.labels.app === "kindnet" || pod.labels["k8s-app"] === "kindnet" },
  { cni: "Flannel", enforces: false, matches: (pod) => pod.labels.app === "flannel" || pod.labels["k8s-app"] === "flannel" },
];

export const detectCni = (pods: readonly PodInfo[], served: { readonly cilium: boolean; readonly calico: boolean }): CniDetection => {
  const found = agents.filter((agent) => pods.some(agent.matches));
  const names = found.map((agent) => agent.cni);
  const notes: string[] = [];

  if (names.includes("Cilium")) {
    if (names.includes("Calico")) notes.push("Both Cilium and Calico agents run here; Cilium's semantics are assumed.");

    return { mode: "cilium", cni: "Cilium", enforcesNetworkPolicy: true, notes };
  }

  if (names.includes("Calico")) return { mode: "calico", cni: "Calico", enforcesNetworkPolicy: true, notes };

  if (served.cilium) {
    notes.push("Cilium's policy kinds are served, but no Cilium agent pod is visible: assuming Cilium enforces.");

    return { mode: "cilium", enforcesNetworkPolicy: "unknown", notes };
  }

  if (served.calico) {
    notes.push("Calico's policy kinds are served, but no calico-node pod is visible: assuming Calico enforces.");

    return { mode: "calico", enforcesNetworkPolicy: "unknown", notes };
  }

  const other = found[0];

  if (other && !other.enforces) {
    notes.push(`${other.cni} does not enforce NetworkPolicy on its own: the verdicts below are what the policies say, not what the network does.`);
  } else if (!other) {
    notes.push("No known CNI agent is visible. Whether NetworkPolicy is enforced depends on the CNI: the verdicts below are what the policies say.");
  }

  return { mode: "kubernetes", cni: other?.cni, enforcesNetworkPolicy: other ? other.enforces : "unknown", notes };
};

export interface NetworkSources {
  readonly kubernetesPolicies: readonly Json[];
  readonly ciliumPolicies: readonly Json[];
  readonly calicoPolicies: readonly Json[];
  readonly calicoTiers: readonly Json[];
  readonly namespaces: readonly Json[];
}

export const namespaceContextOf = (namespaces: readonly Json[]): ClusterContext => {
  const labelsByName = new Map<string, Record<string, string>>(
    namespaces.map((namespace) => [
      namespace.metadata.name,
      // Kubernetes sets this label itself; older clusters, or test data, may lack it.
      { "kubernetes.io/metadata.name": namespace.metadata.name, ...(namespace.metadata.labels ?? {}) },
    ]),
  );

  return { namespaceLabels: (name) => labelsByName.get(name) ?? { "kubernetes.io/metadata.name": name } };
};

export const buildNetworkModel = (mode: EnforcementMode, sources: NetworkSources): NetworkModel => {
  const kubernetes = sources.kubernetesPolicies.flatMap((policy) =>
    normalizeKubernetesNetworkPolicy(policy, { ipBlocksSelectPods: mode !== "cilium", calicoOrder: mode === "calico" ? 1000 : undefined }),
  );
  const cilium = mode === "cilium" ? sources.ciliumPolicies.flatMap(normalizeCiliumPolicy) : [];
  const calico = mode === "calico" ? sources.calicoPolicies.flatMap(normalizeCalicoPolicy) : [];
  const tiers = new Map<string, CalicoTier>(sources.calicoTiers.map((tier) => [tier.metadata.name, toCalicoTier(tier)]));

  return { mode, policies: [...kubernetes, ...cilium, ...calico], tiers, context: namespaceContextOf(sources.namespaces) };
};
