/** Pods and services as the network engine reads them, from the resources the cluster serves. */

import type { ContainerPort, PodInfo, Protocol } from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any -- raw resources from the cluster */
type Json = any;

const asArray = <T>(value: T[] | T | undefined | null): T[] => (Array.isArray(value) ? value : value == null ? [] : [value]);

const protocolOf = (protocol: unknown): Protocol => (protocol === "UDP" || protocol === "SCTP" ? protocol : "TCP");

/** ReplicaSets carry their template hash as a suffix; the Deployment's name is what is left. */
const workloadOf = (pod: Json): PodInfo["workload"] => {
  const owner = asArray<Json>(pod.metadata?.ownerReferences).find((reference) => reference.controller) ?? asArray<Json>(pod.metadata?.ownerReferences)[0];

  if (!owner) return { kind: "Pod", name: pod.metadata.name };

  if (owner.kind === "ReplicaSet") {
    const hash = pod.metadata?.labels?.["pod-template-hash"];

    if (hash && String(owner.name).endsWith(`-${hash}`)) return { kind: "Deployment", name: String(owner.name).slice(0, -(hash.length + 1)) };

    return { kind: "ReplicaSet", name: owner.name };
  }

  if (owner.kind === "Job") {
    const cronJob = /^(.*)-\d{8,}$/.exec(String(owner.name));

    return cronJob ? { kind: "CronJob", name: cronJob[1]! } : { kind: "Job", name: owner.name };
  }

  return { kind: owner.kind, name: owner.name };
};

export const toPodInfo = (pod: Json): PodInfo => {
  const ports: ContainerPort[] = [...asArray<Json>(pod.spec?.containers), ...asArray<Json>(pod.spec?.initContainers)].flatMap((container) =>
    asArray<Json>(container.ports).map((port) => ({
      name: port.name,
      port: port.containerPort,
      protocol: protocolOf(port.protocol),
      container: container.name,
    })),
  );
  const ips = [...new Set([...asArray<Json>(pod.status?.podIPs).map((entry) => entry.ip), pod.status?.podIP].filter(Boolean))] as string[];

  return {
    uid: pod.metadata.uid ?? `${pod.metadata.namespace}/${pod.metadata.name}`,
    namespace: pod.metadata.namespace,
    name: pod.metadata.name,
    labels: pod.metadata.labels ?? {},
    ips,
    ports,
    serviceAccount: pod.spec?.serviceAccountName ?? pod.spec?.serviceAccount ?? "default",
    hostNetwork: pod.spec?.hostNetwork === true,
    phase: pod.status?.phase,
    nodeName: pod.spec?.nodeName,
    workload: workloadOf(pod),
  };
};

/** Pods that hold a network identity: neither finished nor failed. */
export const isLivePod = (pod: PodInfo) => pod.phase !== "Succeeded" && pod.phase !== "Failed";

export interface ServicePortInfo {
  readonly name?: string;
  readonly port: number;
  readonly targetPort: number | string;
  readonly protocol: Protocol;
}

export interface ServiceInfo {
  readonly namespace: string;
  readonly name: string;
  readonly type: string;
  readonly selector?: Readonly<Record<string, string>>;
  readonly clusterIps: readonly string[];
  readonly ports: readonly ServicePortInfo[];
}

export const toServiceInfo = (service: Json): ServiceInfo => ({
  namespace: service.metadata.namespace,
  name: service.metadata.name,
  type: service.spec?.type ?? "ClusterIP",
  selector: service.spec?.selector && Object.keys(service.spec.selector).length > 0 ? service.spec.selector : undefined,
  clusterIps: asArray<string>(service.spec?.clusterIPs ?? service.spec?.clusterIP).filter((ip) => ip && ip !== "None"),
  ports: asArray<Json>(service.spec?.ports).map((port) => ({
    name: port.name,
    port: port.port,
    targetPort: port.targetPort ?? port.port,
    protocol: protocolOf(port.protocol),
  })),
});

export const backendsOf = (service: ServiceInfo, pods: readonly PodInfo[]) =>
  service.selector
    ? pods.filter(
        (pod) => pod.namespace === service.namespace && Object.entries(service.selector!).every(([key, value]) => pod.labels[key] === value),
      )
    : [];

/** The container port a service port reaches on one backend: the target port, or the port of that name. */
export const targetPortOn = (servicePort: ServicePortInfo, pod: PodInfo): number | undefined => {
  if (typeof servicePort.targetPort === "number") return servicePort.targetPort;
  if (/^\d+$/.test(servicePort.targetPort)) return Number(servicePort.targetPort);

  return pod.ports.find((port) => port.name === servicePort.targetPort && port.protocol === servicePort.protocol)?.port;
};
