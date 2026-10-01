/**
 * Network policies of every engine, normalized: which pods a policy selects, and an ordered list
 * of rules, each a predicate over a flow saying whether it matches and what it then does.
 */

export type Protocol = "TCP" | "UDP" | "SCTP";

export type Direction = "ingress" | "egress";

export type NetEngine = "kubernetes" | "cilium" | "calico";

export const netEngineLabel: Record<NetEngine, string> = { kubernetes: "Kubernetes", cilium: "Cilium", calico: "Calico" };

export interface ContainerPort {
  readonly name?: string;
  readonly port: number;
  readonly protocol: Protocol;
  readonly container: string;
}

export interface PodInfo {
  readonly uid: string;
  readonly namespace: string;
  readonly name: string;
  readonly labels: Readonly<Record<string, string>>;
  readonly ips: readonly string[];
  readonly ports: readonly ContainerPort[];
  readonly serviceAccount: string;
  readonly hostNetwork: boolean;
  readonly phase?: string;
  readonly nodeName?: string;
  /** The workload the pod belongs to: its Deployment, StatefulSet, … or the pod itself. */
  readonly workload: { readonly kind: string; readonly name: string };
  /** A stand-in for a workload written in the policy lab, not a pod of the cluster. */
  readonly lab?: boolean;
}

export type Endpoint = { readonly type: "pod"; readonly pod: PodInfo } | { readonly type: "external"; readonly ip: string };

export const endpointLabel = (endpoint: Endpoint) => (endpoint.type === "pod" ? `${endpoint.pod.namespace}/${endpoint.pod.name}` : endpoint.ip);

export const endpointIps = (endpoint: Endpoint) => (endpoint.type === "pod" ? endpoint.pod.ips : [endpoint.ip]);

export interface Traffic {
  readonly port: number;
  readonly protocol: Protocol;
}

/** What a rule is matched against: the pod the policy selects, the other end, and which of the two receives. */
export interface Flow {
  readonly direction: Direction;
  /** The pod the policy selected: the destination for ingress, the source for egress. */
  readonly local: PodInfo;
  readonly peer: Endpoint;
  readonly traffic: Traffic;
}

/** The pod receiving a flow, if it is a pod: what a named port is looked up in. */
export const receiverOf = (flow: Flow): PodInfo | undefined =>
  flow.direction === "ingress" ? flow.local : flow.peer.type === "pod" ? flow.peer.pod : undefined;

export interface ClusterContext {
  readonly namespaceLabels: (namespace: string) => Readonly<Record<string, string>>;
}

export type RuleAction = "allow" | "deny" | "pass" | "log";

export interface NetRule {
  readonly index: number;
  readonly action: RuleAction;
  /** The rule in words: who it lets in, or out, and on which ports. */
  readonly text: string;
  /** What the view cannot settle, such as L7 filters or DNS names. */
  readonly caveats: readonly string[];
  readonly matches: (flow: Flow, context: ClusterContext) => boolean;
}

export interface NetPolicyRef {
  readonly engine: NetEngine;
  readonly kind: string;
  readonly name: string;
  readonly namespace?: string;
}

export const netPolicyRefKey = (ref: NetPolicyRef) => `${ref.engine}:${ref.kind}:${ref.namespace ?? ""}/${ref.name}`;

export const netPolicyRefLabel = (ref: NetPolicyRef) => `${ref.kind} ${ref.namespace ? `${ref.namespace}/` : ""}${ref.name}`;

export interface NetPolicy {
  readonly ref: NetPolicyRef;
  readonly direction: Direction;
  readonly selects: (pod: PodInfo, context: ClusterContext) => boolean;
  readonly selectorText: string;
  readonly rules: readonly NetRule[];
  /**
   * Whether selecting a pod puts it in default deny for the direction: true for Kubernetes and
   * Cilium policies (unless Cilium's enableDefaultDeny says otherwise); Calico decides by tier.
   */
  readonly isolates: boolean;
  readonly tier?: string;
  readonly order?: number;
  readonly problems: readonly string[];
}

const protocolNumbers: Record<string, Protocol> = { "6": "TCP", "17": "UDP", "132": "SCTP" };

export const normalizeProtocol = (protocol: unknown): Protocol | "ANY" | string => {
  if (protocol === undefined || protocol === null || protocol === "") return "ANY";

  const text = String(protocol).toUpperCase();

  return protocolNumbers[text] ?? text;
};

/** A port as written in a policy: a number, a name, or (Calico) a range "8000:8080". */
export const portSpecMatches = (
  spec: number | string | undefined | null,
  endPort: number | undefined | null,
  traffic: Traffic,
  receiver: PodInfo | undefined,
): boolean => {
  if (spec === undefined || spec === null || spec === "" || spec === 0 || spec === "0") return true;

  if (typeof spec === "number" || /^\d+$/.test(spec)) {
    const start = Number(spec);
    const end = endPort ?? start;

    return traffic.port >= start && traffic.port <= end;
  }

  const range = /^(\d+):(\d+)$/.exec(spec);

  if (range) return traffic.port >= Number(range[1]) && traffic.port <= Number(range[2]);

  // A named port is the receiving pod's container port of that name and protocol.
  return receiver?.ports.some((port) => port.name === spec && port.port === traffic.port && port.protocol === traffic.protocol) ?? false;
};

export const describePort = (spec: number | string | undefined | null, endPort: number | undefined | null, protocol: string) => {
  const proto = protocol === "ANY" ? "" : `${protocol} `;

  if (spec === undefined || spec === null || spec === "" || spec === 0 || spec === "0") return protocol === "ANY" ? "any port" : `any ${protocol} port`;

  return endPort ? `${proto}${spec}–${endPort}` : `${proto}${spec}`;
};
