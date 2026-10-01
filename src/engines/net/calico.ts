/**
 * Calico NetworkPolicy and GlobalNetworkPolicy (crd.projectcalico.org/v1 and projectcalico.org/v3),
 * normalized. Calico evaluates policies in tiers, each in order, and the first rule that matches
 * decides: Allow, Deny, or Pass to the next tier.
 */

import { inBlock } from "./ip";
import { type CalicoSelector, safeCalicoSelector } from "./calico-selector";
import {
  type ClusterContext,
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
  type Traffic,
} from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any -- raw resources from the cluster */
type Json = any;

const asArray = <T>(value: T[] | T | undefined | null): T[] => (Array.isArray(value) ? value : value == null ? [] : [value]);

/** The labels Calico matches a pod's selector against: its own, and the ones Calico adds. */
export const calicoLabelsOf = (pod: PodInfo): Record<string, string> => ({
  ...pod.labels,
  "projectcalico.org/namespace": pod.namespace,
  "projectcalico.org/orchestrator": "k8s",
  "projectcalico.org/serviceaccount": pod.serviceAccount,
});

const namespaceLabelsOf = (namespace: string, context: ClusterContext) => ({
  ...context.namespaceLabels(namespace),
  "projectcalico.org/name": namespace,
});

const actionOf = (action: unknown): RuleAction => {
  switch (String(action ?? "").toLowerCase()) {
    case "allow":
      return "allow";
    case "deny":
      return "deny";
    case "pass":
      return "pass";
    default:
      return "log";
  }
};

interface EntityMatcher {
  readonly text: string;
  readonly problems: readonly string[];
  readonly matches: (endpoint: Endpoint, context: ClusterContext) => boolean;
  readonly portsMatch: (traffic: Traffic, receiver: PodInfo | undefined) => boolean;
  readonly hasPorts: boolean;
}

const selectorOrProblem = (text: string | undefined, problems: string[]): CalicoSelector | undefined => {
  if (text === undefined || text === null) return undefined;

  const { selector, error } = safeCalicoSelector(text);

  if (error) problems.push(error);

  return selector;
};

const entityMatcher = (entity: Json, policyNamespace: string | undefined): EntityMatcher => {
  const problems: string[] = [];
  const selector = selectorOrProblem(entity?.selector, problems);
  const notSelector = selectorOrProblem(entity?.notSelector, problems);
  const namespaceSelector = selectorOrProblem(entity?.namespaceSelector, problems);
  const nets = asArray<string>(entity?.nets);
  const notNets = asArray<string>(entity?.notNets);
  const accounts = entity?.serviceAccounts;
  const accountNames = asArray<string>(accounts?.names);
  const ports = asArray<number | string>(entity?.ports);
  const notPorts = asArray<number | string>(entity?.notPorts);

  if (accounts?.selector) problems.push("serviceAccounts.selector is not evaluated");
  if (entity?.services) problems.push("services matches are not evaluated");

  // Pods are scoped to the policy's namespace unless the rule names namespaces itself.
  const needsPod = selector !== undefined || namespaceSelector !== undefined || accountNames.length > 0 || Boolean(entity?.services);

  const parts = [
    entity?.selector !== undefined ? `pods ${entity.selector}` : undefined,
    entity?.notSelector !== undefined ? `not ${entity.notSelector}` : undefined,
    entity?.namespaceSelector !== undefined ? `in namespaces ${entity.namespaceSelector}` : needsPod && policyNamespace ? `in ${policyNamespace}` : undefined,
    accountNames.length > 0 ? `service accounts ${accountNames.join(", ")}` : undefined,
    nets.length > 0 ? nets.join(", ") : undefined,
    notNets.length > 0 ? `not ${notNets.join(", ")}` : undefined,
  ].filter(Boolean);

  return {
    text: parts.length > 0 ? parts.join(" ") : "anywhere",
    problems,
    hasPorts: ports.length > 0 || notPorts.length > 0,
    portsMatch: (traffic, receiver) =>
      (ports.length === 0 || ports.some((port) => portSpecMatches(port, undefined, traffic, receiver))) &&
      !notPorts.some((port) => portSpecMatches(port, undefined, traffic, receiver)),
    matches: (endpoint, context) => {
      const ips = endpoint.type === "pod" ? endpoint.pod.ips : [endpoint.ip];

      if (nets.length > 0 && !ips.some((ip) => nets.some((net) => inBlock(net, [], ip)))) return false;
      if (notNets.some((net) => ips.some((ip) => inBlock(net, [], ip)))) return false;

      if (needsPod) {
        if (endpoint.type !== "pod") return false;

        const pod = endpoint.pod;

        if (namespaceSelector) {
          if (!namespaceSelector(namespaceLabelsOf(pod.namespace, context))) return false;
        } else if (policyNamespace && pod.namespace !== policyNamespace) {
          return false;
        }

        if (selector && !selector(calicoLabelsOf(pod))) return false;
        if (accountNames.length > 0 && !accountNames.includes(pod.serviceAccount)) return false;
      }

      if (notSelector && endpoint.type === "pod" && notSelector(calicoLabelsOf(endpoint.pod))) return false;

      return true;
    },
  };
};

const protocolText = (rule: Json) => {
  const protocol = rule.protocol !== undefined ? normalizeProtocol(rule.protocol) : undefined;
  const not = rule.notProtocol !== undefined ? `not ${normalizeProtocol(rule.notProtocol)}` : undefined;

  return [protocol, not].filter(Boolean).join(" ");
};

const portsText = (entity: Json) => {
  const ports = asArray(entity?.ports).join(", ");
  const notPorts = asArray(entity?.notPorts).join(", ");

  return [ports ? `ports ${ports}` : "", notPorts ? `not ports ${notPorts}` : ""].filter(Boolean).join(" ") || "any port";
};

const toRule = (rule: Json, index: number, direction: Direction, policyNamespace: string | undefined): { rule: NetRule; problems: string[] } => {
  const source = entityMatcher(rule.source, policyNamespace);
  const destination = entityMatcher(rule.destination, policyNamespace);
  const action = actionOf(rule.action);
  const protocol = rule.protocol !== undefined ? normalizeProtocol(rule.protocol) : undefined;
  const notProtocol = rule.notProtocol !== undefined ? normalizeProtocol(rule.notProtocol) : undefined;
  const caveats: string[] = [];

  if (rule.http) caveats.push("HTTP match criteria: only some requests are matched");
  if (asArray(rule.source?.ports).length > 0) caveats.push("source ports are not evaluated");
  if (protocol === "ICMP" || protocol === "ICMPV6") caveats.push("ICMP rules never match TCP, UDP or SCTP traffic");

  const peerText = (direction === "ingress" ? source : destination).text;
  const proto = protocolText(rule);

  const matches = (flow: Flow, context: ClusterContext) => {
    if (protocol !== undefined && protocol !== flow.traffic.protocol) return false;
    if (notProtocol !== undefined && notProtocol === flow.traffic.protocol) return false;

    const localEndpoint: Endpoint = { type: "pod", pod: flow.local };
    const sourceEndpoint = direction === "ingress" ? flow.peer : localEndpoint;
    const destinationEndpoint = direction === "ingress" ? localEndpoint : flow.peer;

    // Source ports are not modelled; destination ports are the flow's port.
    return (
      source.matches(sourceEndpoint, context) &&
      destination.matches(destinationEndpoint, context) &&
      destination.portsMatch(flow.traffic, receiverOf(flow))
    );
  };

  return {
    problems: [...source.problems, ...destination.problems],
    rule: {
      index,
      action,
      text: `${action[0]!.toUpperCase()}${action.slice(1)} ${direction === "ingress" ? "from" : "to"} ${peerText}${proto ? `, ${proto}` : ""}, on ${portsText(
        rule.destination,
      )}${direction === "ingress" && rule.destination?.selector ? ` (only to pods ${rule.destination.selector})` : ""}`,
      caveats,
      matches,
    },
  };
};

/** Calico's default: Ingress, plus Egress when egress rules are given; Egress alone when only those are. */
const typesOf = (spec: Json): Direction[] => {
  const listed = asArray<string>(spec?.types).map((type) => type.toLowerCase());

  if (listed.length > 0) return listed.filter((type): type is Direction => type === "ingress" || type === "egress");

  const hasIngress = spec?.ingress !== undefined;
  const hasEgress = spec?.egress !== undefined;

  return [...(hasIngress || !hasEgress ? (["ingress"] as const) : []), ...(hasEgress ? (["egress"] as const) : [])];
};

/** Calico names a policy outside the default tier `<tier>.<name>`. */
export const calicoTierOf = (policy: Json): string => policy.spec?.tier ?? "default";

export const normalizeCalicoPolicy = (policy: Json): NetPolicy[] => {
  const global = policy.kind === "GlobalNetworkPolicy";
  const namespace: string | undefined = global ? undefined : policy.metadata.namespace;
  const spec = policy.spec ?? {};
  const ref = { engine: "calico" as const, kind: policy.kind ?? "NetworkPolicy", name: policy.metadata.name, namespace };
  const problems: string[] = [];
  const selector = selectorOrProblem(spec.selector ?? "all()", problems) ?? (() => true);
  const namespaceSelector = global ? selectorOrProblem(spec.namespaceSelector, problems) : undefined;

  if (spec.serviceAccountSelector) problems.push("serviceAccountSelector is not evaluated: the policy is treated as selecting regardless");
  if (spec.doNotTrack || spec.preDNAT || spec.applyOnForward) problems.push("host endpoint options (doNotTrack, preDNAT, applyOnForward) are not evaluated");

  const selectorText = `${spec.selector ?? "all()"}${global ? (spec.namespaceSelector ? ` in namespaces ${spec.namespaceSelector}` : " in every namespace") : ` in ${namespace}`}`;

  return typesOf(spec).map((direction) => {
    const rules = asArray<Json>(direction === "ingress" ? spec.ingress : spec.egress).map((rule, index) => toRule(rule, index, direction, namespace));

    return {
      ref,
      direction,
      selectorText,
      isolates: true,
      tier: calicoTierOf(policy),
      order: typeof spec.order === "number" ? spec.order : undefined,
      problems: [...problems, ...rules.flatMap((entry) => entry.problems)],
      rules: rules.map((entry) => entry.rule),
      selects: (pod: PodInfo, context: ClusterContext) =>
        (!namespace || pod.namespace === namespace) &&
        (!namespaceSelector || namespaceSelector(namespaceLabelsOf(pod.namespace, context))) &&
        selector(calicoLabelsOf(pod)),
    };
  });
};

export interface CalicoTier {
  readonly name: string;
  readonly order: number;
  readonly defaultAction: "Deny" | "Pass";
}

export const toCalicoTier = (tier: Json): CalicoTier => ({
  name: tier.metadata.name,
  order: typeof tier.spec?.order === "number" ? tier.spec.order : Number.POSITIVE_INFINITY,
  defaultAction: tier.spec?.defaultAction === "Pass" ? "Pass" : "Deny",
});

/** The tier Kubernetes policies and untiered Calico policies live in, last unless told otherwise. */
export const defaultCalicoTier: CalicoTier = { name: "default", order: 1_000_000, defaultAction: "Deny" };
