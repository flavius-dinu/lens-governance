/**
 * Whether a flow is allowed: the egress side of the source and the ingress side of the
 * destination each have to let it through, by the semantics of the CNI that enforces them.
 */

import { type CalicoTier, defaultCalicoTier } from "./calico";
import {
  type ClusterContext,
  type Direction,
  type Endpoint,
  type Flow,
  type NetEngine,
  type NetPolicy,
  type NetRule,
  type PodInfo,
  type Protocol,
  type Traffic,
} from "./model";
import { backendsOf, type ServiceInfo, type ServicePortInfo, targetPortOn } from "./pods";

/**
 * Which semantics decide: plain Kubernetes NetworkPolicy (whatever CNI enforces it), Cilium
 * (deny wins, then any allow), or Calico (tiers, then order, first match).
 */
export type EnforcementMode = NetEngine;

export interface NetworkModel {
  readonly mode: EnforcementMode;
  readonly policies: readonly NetPolicy[];
  readonly tiers: ReadonlyMap<string, CalicoTier>;
  readonly context: ClusterContext;
}

export interface RuleTrace {
  readonly rule: NetRule;
  readonly matched: boolean;
}

export interface PolicyTrace {
  readonly policy: NetPolicy;
  readonly rules: readonly RuleTrace[];
}

export type SideReason =
  | "not-isolated"
  | "allowed-by-rule"
  | "denied-by-rule"
  | "no-rule-allows"
  | "end-of-tier"
  | "host-network"
  | "not-a-pod";

export interface SideVerdict {
  readonly direction: Direction;
  readonly allowed: boolean;
  readonly reason: SideReason;
  /** The rule that decided, when one did. */
  readonly decidedBy?: { readonly policy: NetPolicy; readonly rule: NetRule };
  readonly summary: string;
  /** Every policy that selected the pod for this direction, with which of its rules matched. */
  readonly trace: readonly PolicyTrace[];
  readonly caveats: readonly string[];
}

const describeDecider = (policy: NetPolicy, rule: NetRule) =>
  `${policy.ref.kind} ${policy.ref.namespace ? `${policy.ref.namespace}/` : ""}${policy.ref.name}, rule ${rule.index + 1}`;

const traceOf = (selecting: readonly NetPolicy[], flow: Flow, context: ClusterContext): PolicyTrace[] =>
  selecting.map((policy) => ({ policy, rules: policy.rules.map((rule) => ({ rule, matched: rule.matches(flow, context) })) }));

const caveatsOf = (trace: readonly PolicyTrace[]) => [
  ...new Set(trace.flatMap((entry) => [...entry.policy.problems, ...entry.rules.filter((rule) => rule.matched).flatMap((rule) => rule.rule.caveats)])),
];

const evaluateUnion = (selecting: readonly NetPolicy[], flow: Flow, context: ClusterContext, direction: Direction): SideVerdict => {
  const trace = traceOf(selecting, flow, context);
  const caveats = caveatsOf(trace);
  const matched = (action: "allow" | "deny") =>
    trace.flatMap((entry) => entry.rules.filter((rule) => rule.matched && rule.rule.action === action).map((rule) => ({ policy: entry.policy, rule: rule.rule })));
  const denied = matched("deny")[0];

  if (denied) {
    return { direction, allowed: false, reason: "denied-by-rule", decidedBy: denied, summary: `Denied by ${describeDecider(denied.policy, denied.rule)}`, trace, caveats };
  }

  const isolating = selecting.filter((policy) => policy.isolates);
  const allowed = matched("allow")[0];

  if (isolating.length === 0) {
    return {
      direction,
      allowed: true,
      reason: "not-isolated",
      decidedBy: allowed,
      summary: selecting.length === 0 ? `No policy selects the pod for ${direction}: everything is allowed` : `No policy puts the pod in default deny for ${direction}`,
      trace,
      caveats,
    };
  }

  if (allowed) {
    return { direction, allowed: true, reason: "allowed-by-rule", decidedBy: allowed, summary: `Allowed by ${describeDecider(allowed.policy, allowed.rule)}`, trace, caveats };
  }

  return {
    direction,
    allowed: false,
    reason: "no-rule-allows",
    summary: `Denied: ${isolating.length === 1 ? "the policy" : `${isolating.length} policies`} selecting the pod for ${direction} allow nothing that matches`,
    trace,
    caveats,
  };
};

const tierOf = (model: NetworkModel, policy: NetPolicy) => model.tiers.get(policy.tier ?? "default") ?? (policy.tier === "default" || !policy.tier ? defaultCalicoTier : { name: policy.tier, order: Number.POSITIVE_INFINITY, defaultAction: "Deny" as const });

const byOrder = (a: NetPolicy, b: NetPolicy) =>
  (a.order ?? Number.POSITIVE_INFINITY) - (b.order ?? Number.POSITIVE_INFINITY) || a.ref.name.localeCompare(b.ref.name);

const evaluateTiered = (model: NetworkModel, selecting: readonly NetPolicy[], flow: Flow, direction: Direction): SideVerdict => {
  const trace = traceOf(selecting, flow, model.context);
  const caveats = caveatsOf(trace);
  const traceByPolicy = new Map(trace.map((entry) => [entry.policy, entry]));
  const tiers = new Map<string, { tier: CalicoTier; policies: NetPolicy[] }>();

  for (const policy of selecting) {
    const tier = tierOf(model, policy);
    const entry = tiers.get(tier.name) ?? { tier, policies: [] };

    entry.policies.push(policy);
    tiers.set(tier.name, entry);
  }

  const ordered = [...tiers.values()].sort((a, b) => a.tier.order - b.tier.order || a.tier.name.localeCompare(b.tier.name));

  for (const { tier, policies } of ordered) {
    let passed = false;

    for (const policy of policies.sort(byOrder)) {
      for (const { rule, matched } of traceByPolicy.get(policy)!.rules) {
        if (!matched || rule.action === "log") continue;

        if (rule.action === "pass") {
          passed = true;
          break;
        }

        const decidedBy = { policy, rule };

        return rule.action === "allow"
          ? { direction, allowed: true, reason: "allowed-by-rule", decidedBy, summary: `Allowed by ${describeDecider(policy, rule)} (tier ${tier.name})`, trace, caveats }
          : { direction, allowed: false, reason: "denied-by-rule", decidedBy, summary: `Denied by ${describeDecider(policy, rule)} (tier ${tier.name})`, trace, caveats };
      }

      if (passed) break;
    }

    if (!passed && tier.defaultAction === "Deny") {
      return {
        direction,
        allowed: false,
        reason: "end-of-tier",
        summary: `Denied at the end of tier ${tier.name}: policies there select the pod for ${direction}, and no rule matches`,
        trace,
        caveats,
      };
    }
  }

  return {
    direction,
    allowed: true,
    reason: "not-isolated",
    summary: selecting.length === 0 ? `No policy selects the pod for ${direction}: everything is allowed` : "Every tier passed: allowed by the profile",
    trace,
    caveats,
  };
};

export const evaluateSide = (model: NetworkModel, direction: Direction, local: PodInfo, peer: Endpoint, traffic: Traffic): SideVerdict => {
  if (local.hostNetwork) {
    return {
      direction,
      allowed: true,
      reason: "host-network",
      summary: `The pod uses the host network: pod network policies do not apply to its ${direction}`,
      trace: [],
      caveats: [],
    };
  }

  const flow: Flow = { direction, local, peer, traffic };
  const selecting = model.policies.filter((policy) => policy.direction === direction && policy.selects(local, model.context));

  return model.mode === "calico" ? evaluateTiered(model, selecting, flow, direction) : evaluateUnion(selecting, flow, model.context, direction);
};

export interface FlowVerdict {
  readonly allowed: boolean;
  readonly source: Endpoint;
  readonly destination: Endpoint;
  readonly traffic: Traffic;
  /** Undefined when the source is outside the cluster, where no egress policy of the cluster applies. */
  readonly egress?: SideVerdict;
  readonly ingress?: SideVerdict;
  readonly notes: readonly string[];
}

export const evaluateFlow = (model: NetworkModel, source: Endpoint, destination: Endpoint, traffic: Traffic): FlowVerdict => {
  const notes: string[] = [];

  if (source.type === "pod" && destination.type === "pod" && source.pod.uid === destination.pod.uid) {
    notes.push("A pod reaching itself is not subject to network policy.");

    return { allowed: true, source, destination, traffic, notes };
  }

  const egress = source.type === "pod" ? evaluateSide(model, "egress", source.pod, destination, traffic) : undefined;
  const ingress = destination.type === "pod" ? evaluateSide(model, "ingress", destination.pod, source, traffic) : undefined;

  if (destination.type === "pod" && !destination.pod.ports.some((port) => port.port === traffic.port && port.protocol === traffic.protocol)) {
    notes.push(`${destination.pod.name} declares no container port ${traffic.protocol} ${traffic.port}: policy allows it, but something has to listen.`);
  }

  if (destination.type === "pod" && destination.pod.ips.length === 0) notes.push(`${destination.pod.name} has no IP yet.`);

  return { allowed: (egress?.allowed ?? true) && (ingress?.allowed ?? true), source, destination, traffic, egress, ingress, notes };
};

export interface BackendVerdict {
  readonly pod: PodInfo;
  readonly targetPort?: number;
  readonly verdict?: FlowVerdict;
  readonly problem?: string;
}

export interface ServiceVerdict {
  readonly service: ServiceInfo;
  readonly servicePort: ServicePortInfo;
  readonly backends: readonly BackendVerdict[];
  /** Allowed to at least one backend: what a client sees, as the service balances over all of them. */
  readonly anyAllowed: boolean;
  readonly allAllowed: boolean;
  readonly notes: readonly string[];
}

/** Network policy sees a service's traffic after it is translated: to each backend, on its target port. */
export const evaluateServiceFlow = (
  model: NetworkModel,
  source: Endpoint,
  service: ServiceInfo,
  servicePort: ServicePortInfo,
  pods: readonly PodInfo[],
): ServiceVerdict => {
  const notes: string[] = [];

  if (!service.selector) notes.push("The service has no selector: its endpoints are managed by hand and are not resolved here.");
  if (service.type === "ExternalName") notes.push("An ExternalName service is a DNS alias: the flow goes to an address outside the cluster.");

  const backends = backendsOf(service, pods).map((pod): BackendVerdict => {
    const targetPort = targetPortOn(servicePort, pod);

    if (targetPort === undefined) return { pod, problem: `no container port named ${servicePort.targetPort}` };

    return { pod, targetPort, verdict: evaluateFlow(model, source, { type: "pod", pod }, { port: targetPort, protocol: servicePort.protocol }) };
  });

  if (service.selector && backends.length === 0) notes.push("No running pod matches the service's selector.");

  const verdicts = backends.filter((backend) => backend.verdict);

  return {
    service,
    servicePort,
    backends,
    anyAllowed: verdicts.some((backend) => backend.verdict!.allowed),
    allAllowed: verdicts.length > 0 && verdicts.every((backend) => backend.verdict!.allowed),
    notes,
  };
};

/** The cluster's DNS pods, which a pod resolving a service by name has to reach first. */
export const dnsPodsOf = (pods: readonly PodInfo[]) =>
  pods.filter((pod) => pod.namespace === "kube-system" && (pod.labels["k8s-app"] === "kube-dns" || pod.labels["k8s-app"] === "coredns"));

// ---------------------------------------------------------------------------------------------
// Matrix and coverage
// ---------------------------------------------------------------------------------------------

export interface WorkloadGroup {
  readonly key: string;
  readonly namespace: string;
  readonly kind: string;
  readonly name: string;
  readonly pods: readonly PodInfo[];
}

export const groupByWorkload = (pods: readonly PodInfo[]): WorkloadGroup[] => {
  const groups = new Map<string, { namespace: string; kind: string; name: string; pods: PodInfo[] }>();

  for (const pod of pods) {
    const key = `${pod.namespace}/${pod.workload.kind}/${pod.workload.name}`;
    const group = groups.get(key) ?? { namespace: pod.namespace, kind: pod.workload.kind, name: pod.workload.name, pods: [] };

    group.pods.push(pod);
    groups.set(key, group);
  }

  return [...groups.entries()]
    .map(([key, group]) => ({ key, ...group }))
    .sort((a, b) => a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name));
};

export type MatrixPorts = { readonly type: "fixed"; readonly traffic: Traffic } | { readonly type: "declared" };

export interface MatrixCell {
  /** Ports tried, and how many of them were allowed. None tried when the destination declares none. */
  readonly tried: number;
  readonly allowed: number;
  readonly ports: readonly { readonly traffic: Traffic; readonly allowed: boolean }[];
}

/** Every pair of workloads, each by one representative pod: pods of a workload share labels, so share policy. */
export const reachabilityMatrix = (model: NetworkModel, groups: readonly WorkloadGroup[], ports: MatrixPorts): MatrixCell[][] =>
  groups.map((source) =>
    groups.map((destination) => {
      const sourcePod = source.pods[0]!;
      const destinationPod = destination.pods[0]!;
      const tried: Traffic[] =
        ports.type === "fixed"
          ? [ports.traffic]
          : [...new Map(destinationPod.ports.map((port) => [`${port.protocol}/${port.port}`, { port: port.port, protocol: port.protocol as Protocol }])).values()];
      const results = tried.map((traffic) => ({
        traffic,
        allowed: evaluateFlow(model, { type: "pod", pod: sourcePod }, { type: "pod", pod: destinationPod }, traffic).allowed,
      }));

      return { tried: results.length, allowed: results.filter((result) => result.allowed).length, ports: results };
    }),
  );

export interface NamespaceCoverage {
  readonly namespace: string;
  readonly pods: number;
  readonly ingressIsolated: number;
  readonly egressIsolated: number;
  readonly policies: number;
  /** A policy selecting every pod of the namespace that allows nothing in that direction. */
  readonly defaultDenyIngress: boolean;
  readonly defaultDenyEgress: boolean;
}

const isolatedFor = (model: NetworkModel, pod: PodInfo, direction: Direction) =>
  !pod.hostNetwork &&
  model.policies.some((policy) => policy.direction === direction && (model.mode === "calico" || policy.isolates) && policy.selects(pod, model.context));

export const coverageOf = (model: NetworkModel, pods: readonly PodInfo[], namespaces: readonly string[]): NamespaceCoverage[] =>
  namespaces.map((namespace) => {
    const inNamespace = pods.filter((pod) => pod.namespace === namespace && !pod.hostNetwork);
    const policies = model.policies.filter((policy) => policy.ref.namespace === namespace || policy.ref.namespace === undefined);
    const denyAll = (direction: Direction) =>
      policies.some(
        (policy) =>
          policy.ref.namespace === namespace &&
          policy.direction === direction &&
          policy.rules.every((rule) => rule.action !== "allow") &&
          inNamespace.every((pod) => policy.selects(pod, model.context)),
      );

    return {
      namespace,
      pods: inNamespace.length,
      ingressIsolated: inNamespace.filter((pod) => isolatedFor(model, pod, "ingress")).length,
      egressIsolated: inNamespace.filter((pod) => isolatedFor(model, pod, "egress")).length,
      policies: new Set(model.policies.filter((policy) => policy.ref.namespace === namespace).map((policy) => policy.ref.name)).size,
      defaultDenyIngress: inNamespace.length > 0 && denyAll("ingress"),
      defaultDenyEgress: inNamespace.length > 0 && denyAll("egress"),
    };
  });

/** Which policies select a pod, per direction: what the pod's own network posture is. */
export const policiesSelecting = (model: NetworkModel, pod: PodInfo) => ({
  ingress: model.policies.filter((policy) => policy.direction === "ingress" && policy.selects(pod, model.context)),
  egress: model.policies.filter((policy) => policy.direction === "egress" && policy.selects(pod, model.context)),
});
