/** Kubernetes NetworkPolicy, normalized: one policy per direction it governs, allow rules only. */

import { describeSelector, isEmptySelector, type LabelSelector, matchesSelector } from "../labels";
import { inBlock } from "./ip";
import {
  type ClusterContext,
  describePort,
  type Direction,
  type Endpoint,
  type Flow,
  type NetPolicy,
  type NetRule,
  normalizeProtocol,
  portSpecMatches,
  receiverOf,
} from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any -- raw resources from the cluster */
type Json = any;

const asArray = <T>(value: T[] | T | undefined | null): T[] => (Array.isArray(value) ? value : value == null ? [] : [value]);

export interface KubernetesNormalizeOptions {
  /**
   * Whether an ipBlock also selects pods by their IP. Calico and most CNIs say yes; Cilium applies
   * CIDR rules only to traffic leaving the cluster.
   */
  readonly ipBlocksSelectPods: boolean;
  /** Order Calico gives Kubernetes policies within its default tier. */
  readonly calicoOrder?: number;
}

const peerMatches = (peer: Json, endpoint: Endpoint, policyNamespace: string, context: ClusterContext, options: KubernetesNormalizeOptions) => {
  if (peer.ipBlock) {
    if (endpoint.type === "pod" && !options.ipBlocksSelectPods) return false;

    const ips = endpoint.type === "pod" ? endpoint.pod.ips : [endpoint.ip];

    return ips.some((ip) => inBlock(peer.ipBlock.cidr, peer.ipBlock.except, ip));
  }

  if (endpoint.type !== "pod") return false;

  const pod = endpoint.pod;

  if (peer.namespaceSelector) {
    if (!matchesSelector(peer.namespaceSelector as LabelSelector, context.namespaceLabels(pod.namespace))) return false;
  } else if (pod.namespace !== policyNamespace) {
    return false;
  }

  return matchesSelector(peer.podSelector as LabelSelector | undefined, pod.labels);
};

const describePeer = (peer: Json): string => {
  if (peer.ipBlock) {
    const except = asArray<string>(peer.ipBlock.except);

    return `${peer.ipBlock.cidr}${except.length > 0 ? ` except ${except.join(", ")}` : ""}`;
  }

  const pods = peer.podSelector && !isEmptySelector(peer.podSelector) ? `pods ${describeSelector(peer.podSelector)}` : "all pods";

  if (!peer.namespaceSelector) return `${pods} in the same namespace`;

  return `${pods} in ${isEmptySelector(peer.namespaceSelector) ? "every namespace" : `namespaces ${describeSelector(peer.namespaceSelector)}`}`;
};

const portMatches = (port: Json, flow: Flow) => {
  const protocol = normalizeProtocol(port.protocol ?? "TCP");

  return protocol === flow.traffic.protocol && portSpecMatches(port.port, port.endPort, flow.traffic, receiverOf(flow));
};

const toRule = (
  rule: Json,
  index: number,
  direction: Direction,
  policyNamespace: string,
  options: KubernetesNormalizeOptions,
): NetRule => {
  const peers = asArray<Json>(direction === "ingress" ? rule.from : rule.to);
  const ports = asArray<Json>(rule.ports);
  const who = peers.length === 0 ? "anywhere" : peers.map(describePeer).join("; or ");
  const where = ports.length === 0 ? "any port" : ports.map((port) => describePort(port.port, port.endPort, normalizeProtocol(port.protocol ?? "TCP"))).join(", ");

  return {
    index,
    action: "allow",
    text: `${direction === "ingress" ? "From" : "To"} ${who}, on ${where}`,
    caveats: peers.some((peer) => peer.ipBlock) && !options.ipBlocksSelectPods ? ["ipBlock does not select pods inside the cluster with this CNI"] : [],
    matches: (flow, context) =>
      (peers.length === 0 || peers.some((peer) => peerMatches(peer, flow.peer, policyNamespace, context, options))) &&
      (ports.length === 0 || ports.some((port) => portMatches(port, flow))),
  };
};

/** The directions a policy governs: as listed, or Ingress plus Egress when egress rules are given. */
export const policyTypesOf = (spec: Json): Direction[] => {
  const listed = asArray<string>(spec?.policyTypes);

  if (listed.length > 0) return listed.map((type) => type.toLowerCase()).filter((type): type is Direction => type === "ingress" || type === "egress");

  return spec?.egress ? ["ingress", "egress"] : ["ingress"];
};

export const normalizeKubernetesNetworkPolicy = (policy: Json, options: KubernetesNormalizeOptions): NetPolicy[] => {
  const spec = policy.spec ?? {};
  const namespace: string = policy.metadata.namespace;
  const ref = { engine: "kubernetes" as const, kind: "NetworkPolicy", name: policy.metadata.name, namespace };
  const selectorText = isEmptySelector(spec.podSelector) ? `every pod in ${namespace}` : `pods ${describeSelector(spec.podSelector)} in ${namespace}`;

  return policyTypesOf(spec).map((direction) => ({
    ref,
    direction,
    selectorText,
    isolates: true,
    tier: options.calicoOrder !== undefined ? "default" : undefined,
    order: options.calicoOrder,
    problems: [],
    selects: (pod) => pod.namespace === namespace && matchesSelector(spec.podSelector as LabelSelector | undefined, pod.labels),
    rules: asArray<Json>(direction === "ingress" ? spec.ingress : spec.egress).map((rule, index) => toRule(rule, index, direction, namespace, options)),
  }));
};
