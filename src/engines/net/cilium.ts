/**
 * CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy, normalized. Cilium allows what any
 * allow rule allows, unless a deny rule matches, which always wins; a pod an ingress (egress)
 * section selects is in default deny for that direction unless enableDefaultDeny turns it off.
 */

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
  type PodInfo,
  portSpecMatches,
  receiverOf,
  type RuleAction,
} from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any -- raw resources from the cluster */
type Json = any;

const asArray = <T>(value: T[] | T | undefined | null): T[] => (Array.isArray(value) ? value : value == null ? [] : [value]);

const namespaceKey = "io.kubernetes.pod.namespace";

/** Cilium writes label sources as prefixes, `k8s:app`, `any:app`; a pod's labels carry none. */
const stripSource = (key: string) => key.replace(/^(k8s|any|container|unspec):/, "");

/** The labels Cilium derives a pod's security identity from. */
export const ciliumIdentityOf = (pod: PodInfo, context: ClusterContext): Record<string, string> => {
  const identity: Record<string, string> = {
    ...pod.labels,
    [namespaceKey]: pod.namespace,
    "io.cilium.k8s.policy.serviceaccount": pod.serviceAccount,
    "io.cilium.k8s.policy.cluster": "default",
  };

  for (const [key, value] of Object.entries(context.namespaceLabels(pod.namespace))) {
    identity[`io.cilium.k8s.namespace.labels.${key}`] = value;
  }

  return identity;
};

const selectorMatches = (selector: LabelSelector | undefined, pod: PodInfo, context: ClusterContext) =>
  matchesSelector(selector, ciliumIdentityOf(pod, context), stripSource);

const namesNamespace = (selector: Json) =>
  Object.keys(selector?.matchLabels ?? {}).some((key) => stripSource(key) === namespaceKey) ||
  asArray<Json>(selector?.matchExpressions).some((expression) => stripSource(expression.key) === namespaceKey);

const entityMatches = (entity: string, endpoint: Endpoint) => {
  switch (entity) {
    case "all":
      return true;
    case "world":
    case "world-ipv4":
    case "world-ipv6":
      return endpoint.type === "external";
    case "cluster":
      return endpoint.type === "pod";
    default:
      // host, remote-node, kube-apiserver, health, init, ingress, unmanaged: not pods or outside addresses.
      return false;
  }
};

const fromOrTo = (rule: Json, direction: Direction, field: string) => rule[`${direction === "ingress" ? "from" : "to"}${field}`];

const l3Fields = ["Endpoints", "Entities", "CIDR", "CIDRSet", "Nodes", "Groups", "FQDNs", "Services", "Requires"];

const describeEndpointSelector = (selector: Json, scopedTo?: string) => {
  const text = isEmptySelector(selector) ? "all endpoints" : `endpoints ${describeSelector(selector)}`;

  return scopedTo && !namesNamespace(selector) ? `${text} in ${scopedTo}` : text;
};

const toRule = (rule: Json, index: number, action: RuleAction, direction: Direction, namespace: string | undefined): NetRule => {
  const endpoints = asArray<Json>(fromOrTo(rule, direction, "Endpoints"));
  const entities = asArray<string>(fromOrTo(rule, direction, "Entities"));
  const cidrs = asArray<string>(fromOrTo(rule, direction, "CIDR"));
  const cidrSets = asArray<Json>(fromOrTo(rule, direction, "CIDRSet"));
  const fqdns = asArray<Json>(direction === "egress" ? rule.toFQDNs : undefined);
  const services = asArray<Json>(direction === "egress" ? rule.toServices : undefined);
  const toPorts = asArray<Json>(rule.toPorts);
  const hasL3 = l3Fields.some((field) => fromOrTo(rule, direction, field) !== undefined);
  const caveats: string[] = [];

  if (fqdns.length > 0) caveats.push(`allows DNS names ${fqdns.map((fqdn) => fqdn.matchName ?? fqdn.matchPattern).join(", ")}, which an IP cannot be checked against`);
  if (services.length > 0) caveats.push("toServices rules are not evaluated");
  if (fromOrTo(rule, direction, "Requires")) caveats.push(`${direction === "ingress" ? "fromRequires" : "toRequires"} is deprecated and not evaluated`);
  if (fromOrTo(rule, direction, "Nodes")) caveats.push("node selectors are not evaluated");

  const l7 = toPorts.flatMap((entry) => Object.keys(entry.rules ?? {}));

  if (l7.length > 0) caveats.push(`L7 filtering (${[...new Set(l7)].join(", ")}): only some requests on the port are allowed`);

  const peerMatches = (peer: Endpoint, context: ClusterContext) => {
    // An empty rule selects nothing; one with only ports is open to every peer on them.
    if (!hasL3) return toPorts.length > 0;

    if (peer.type === "pod") {
      if (
        endpoints.some(
          (selector) => (!namespace || namesNamespace(selector) || peer.pod.namespace === namespace) && selectorMatches(selector, peer.pod, context),
        )
      )
        return true;
    }

    if (entities.some((entity) => entityMatches(entity, peer))) return true;

    if (peer.type === "external") {
      if (cidrs.some((cidr) => inBlock(cidr, [], peer.ip))) return true;
      if (cidrSets.some((set) => set.cidr && inBlock(set.cidr, set.except, peer.ip))) return true;
    }

    return false;
  };

  const portMatches = (flow: Flow) =>
    toPorts.length === 0 ||
    toPorts.some((entry) => {
      const ports = asArray<Json>(entry.ports);

      return (
        ports.length === 0 ||
        ports.some((port) => {
          const protocol = normalizeProtocol(port.protocol);

          return (protocol === "ANY" || protocol === flow.traffic.protocol) && portSpecMatches(port.port, port.endPort, flow.traffic, receiverOf(flow));
        })
      );
    });

  const peers = [
    ...endpoints.map((selector) => describeEndpointSelector(selector, namespace)),
    ...entities.map((entity) => `entity ${entity}`),
    ...cidrs,
    ...cidrSets.map((set) => `${set.cidr ?? set.cidrGroupRef}${asArray(set.except).length ? ` except ${asArray(set.except).join(", ")}` : ""}`),
    ...fqdns.map((fqdn) => `DNS ${fqdn.matchName ?? fqdn.matchPattern}`),
  ];
  const portsText =
    toPorts.length === 0
      ? "any port"
      : toPorts
          .flatMap((entry) => asArray<Json>(entry.ports).map((port) => describePort(port.port, port.endPort, normalizeProtocol(port.protocol))))
          .join(", ") || "any port";
  const who = !hasL3 ? (toPorts.length > 0 ? "anywhere" : "nothing (an empty rule selects no peer)") : peers.join("; or ") || "nothing";

  return {
    index,
    action,
    text: `${action === "deny" ? "Deny " : ""}${direction === "ingress" ? "from" : "to"} ${who}, on ${portsText}`.replace(/^./, (first) => first.toUpperCase()),
    caveats,
    matches: (flow, context) => peerMatches(flow.peer, context) && portMatches(flow),
  };
};

const specsOf = (policy: Json): Json[] => [...(policy.spec ? [policy.spec] : []), ...asArray<Json>(policy.specs)];

export const normalizeCiliumPolicy = (policy: Json): NetPolicy[] => {
  const clusterwide = policy.kind === "CiliumClusterwideNetworkPolicy";
  const namespace: string | undefined = clusterwide ? undefined : policy.metadata.namespace;
  const ref = { engine: "cilium" as const, kind: policy.kind ?? "CiliumNetworkPolicy", name: policy.metadata.name, namespace };

  return specsOf(policy).flatMap((spec, specIndex) => {
    if (!spec.endpointSelector) {
      // Host policies select nodes rather than pods.
      return [];
    }

    const selectorText = `${describeEndpointSelector(spec.endpointSelector)}${namespace && !namesNamespace(spec.endpointSelector) ? ` in ${namespace}` : ""}`;
    const selects = (pod: PodInfo, context: ClusterContext) =>
      (!namespace || pod.namespace === namespace) && selectorMatches(spec.endpointSelector, pod, context);

    return (["ingress", "egress"] as const).flatMap((direction): NetPolicy[] => {
      const allows = spec[direction];
      const denies = spec[`${direction}Deny`];

      if (allows === undefined && denies === undefined) return [];

      return [
        {
          ref: specIndex === 0 ? ref : { ...ref, name: `${ref.name} (spec ${specIndex + 1})` },
          direction,
          selectorText,
          isolates: spec.enableDefaultDeny?.[direction] !== false,
          problems: [],
          selects,
          // Deny first, as Cilium gives deny precedence regardless of order.
          rules: [
            ...asArray<Json>(denies).map((rule, index) => toRule(rule, index, "deny", direction, namespace)),
            ...asArray<Json>(allows).map((rule, index) => toRule(rule, asArray(denies).length + index, "allow", direction, namespace)),
          ],
        },
      ];
    });
  });
};
