import { getInjectable2 } from "@k8slens/injectable";
import { computed } from "mobx";
import { clusterKindInjectable, readKinds } from "../data/cluster-kind.injectable";
import { buildNetworkModel, detectCni } from "../engines/net/build";
import {
  coverageOf,
  dnsPodsOf,
  evaluateFlow,
  evaluateServiceFlow,
  type FlowVerdict,
  groupByWorkload,
  type MatrixPorts,
  reachabilityMatrix,
  type ServiceVerdict,
} from "../engines/net/evaluate";
import { isIp } from "../engines/net/ip";
import { type Endpoint, type PodInfo, type Protocol } from "../engines/net/model";
import { isLivePod, type ServiceInfo, toPodInfo, toServiceInfo } from "../engines/net/pods";
import type { SearchOption } from "../ui/search-filter";
import { overlay as layOver } from "../engines/lab/manifests";
import { isLabUid, labModelInjectable } from "../lab/lab-model.injectable";
import { networkStateInjectable } from "./network-state.injectable";

/* eslint-disable @typescript-eslint/no-explicit-any -- raw resources from the cluster */
type Json = any;

const keys = [
  "pods",
  "namespaces",
  "services",
  "networkPolicies",
  "ciliumPolicies",
  "ciliumClusterwidePolicies",
  "calicoPolicies",
  "calicoGlobalPolicies",
  "calicoTiers",
] as const;

/** The largest matrix drawn: 150 workloads compute in tens of milliseconds, but draw 22,500 cells. */
export const matrixLimit = 150;

/** Stand-ins for "the internet", for the matrix's outside row and column. */
const outsideIp = "203.0.113.10";

const systemNamespaces = new Set(["kube-system", "kube-public", "kube-node-lease", "local-path-storage", "calico-system", "tigera-operator", "cilium"]);

export const isSystemNamespace = (namespace: string) => systemNamespaces.has(namespace) || namespace.endsWith("-system");

const parsePort = (text: string) => {
  const port = Number(text.trim());

  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : undefined;
};

/** Kubernetes lists items without their kind; the normalizers tell clusterwide kinds by it. */
const withKind = (kind: string) => (resource: Json) => ({ kind, ...resource });

export type Resolved =
  | { readonly type: "pod"; readonly endpoint: Endpoint; readonly pod: PodInfo }
  | { readonly type: "service"; readonly service: ServiceInfo }
  | { readonly type: "external"; readonly endpoint: Endpoint }
  | { readonly type: "invalid"; readonly message: string }
  | { readonly type: "empty" };

export type SimulationResult =
  | { readonly type: "incomplete"; readonly message: string }
  | { readonly type: "flow"; readonly verdict: FlowVerdict; readonly dns?: FlowVerdict }
  | { readonly type: "service"; readonly source: Endpoint; readonly verdict: ServiceVerdict; readonly dns?: FlowVerdict };

/** A cluster's network policies, and what they let through, as the network view shows them. */
export const networkModelInjectable = getInjectable2({
  id: "real-governance-network-model",

  instantiate: (di) => {
    const loadOf = di.inject(clusterKindInjectable);
    const stateOf = di.inject(networkStateInjectable);
    const labOf = di.inject(labModelInjectable);

    return (clusterId: string) => {
      const state = stateOf(clusterId);
      const lab = labOf(clusterId);
      const snapshot = computed(() => readKinds(loadOf, clusterId, keys));
      const labOverlay = computed(() => lab.overlay.get());

      const namespaceResources = computed(() => layOver(snapshot.get().items.namespaces as Json[], labOverlay.get().namespaces, withKind("Namespace")));

      const pods = computed(() => {
        const fromLab = labOverlay.get().pods;
        const replaced = new Set(fromLab.map((pod) => `${pod.metadata.namespace}/${pod.metadata.name}`));
        const cluster = (snapshot.get().items.pods as Json[]).map(toPodInfo).filter((pod) => isLivePod(pod) && !replaced.has(`${pod.namespace}/${pod.name}`));

        return [
          ...cluster,
          ...fromLab.map((raw): PodInfo => {
            const pod = toPodInfo(raw);
            const kind = pod.uid.slice("lab:".length, pod.uid.indexOf("/"));

            return { ...pod, workload: { kind, name: pod.name }, lab: isLabUid(pod.uid) };
          }),
        ];
      });
      const services = computed(() => layOver(snapshot.get().items.services as Json[], labOverlay.get().services, withKind("Service")).map(toServiceInfo));
      const namespaces = computed(() => [...new Set([...namespaceResources.get().map((namespace) => namespace.metadata.name as string), ...pods.get().map((pod) => pod.namespace)])].sort());

      const detection = computed(() => {
        const { absent } = snapshot.get();

        return detectCni(pods.get(), { cilium: !absent.has("ciliumPolicies"), calico: !absent.has("calicoPolicies") });
      });

      const model = computed(() => {
        const { items } = snapshot.get();
        const drafts = labOverlay.get();
        const same = (resource: Json) => resource;

        return buildNetworkModel(detection.get().mode, {
          kubernetesPolicies: layOver((items.networkPolicies as Json[]).map(withKind("NetworkPolicy")), drafts.networkPolicies, same),
          ciliumPolicies: layOver(
            [...(items.ciliumPolicies as Json[]).map(withKind("CiliumNetworkPolicy")), ...(items.ciliumClusterwidePolicies as Json[]).map(withKind("CiliumClusterwideNetworkPolicy"))],
            drafts.ciliumPolicies,
            same,
          ),
          calicoPolicies: layOver(
            [...(items.calicoPolicies as Json[]).map(withKind("NetworkPolicy")), ...(items.calicoGlobalPolicies as Json[]).map(withKind("GlobalNetworkPolicy"))],
            drafts.calicoPolicies,
            same,
          ),
          calicoTiers: layOver(items.calicoTiers as Json[], drafts.calicoTiers, withKind("Tier")),
          namespaces: namespaceResources.get(),
        });
      });

      /** Whether a policy of the model is one of the lab's drafts. */
      const isDraftPolicy = (ref: { readonly kind: string; readonly namespace?: string; readonly name: string }) => lab.isDraft(ref.kind, ref.namespace, ref.name.replace(/ \(spec \d+\)$/, ""));

      const podByKey = computed(() => new Map(pods.get().map((pod) => [`${pod.namespace}/${pod.name}`, pod])));
      const serviceByKey = computed(() => new Map(services.get().map((service) => [`${service.namespace}/${service.name}`, service])));

      const resolve = (choice: string, allowService: boolean): Resolved => {
        const text = choice.trim();

        if (!text) return { type: "empty" };

        if (text.startsWith("pod:")) {
          const pod = podByKey.get().get(text.slice(4));

          return pod ? { type: "pod", endpoint: { type: "pod", pod }, pod } : { type: "invalid", message: `No running pod ${text.slice(4)}` };
        }

        if (text.startsWith("svc:")) {
          if (!allowService) return { type: "invalid", message: "A service cannot start a flow: pick one of its pods" };

          const service = serviceByKey.get().get(text.slice(4));

          return service ? { type: "service", service } : { type: "invalid", message: `No service ${text.slice(4)}` };
        }

        if (isIp(text)) {
          const pod = pods.get().find((candidate) => candidate.ips.includes(text));

          return pod ? { type: "pod", endpoint: { type: "pod", pod }, pod } : { type: "external", endpoint: { type: "external", ip: text } };
        }

        // A bare namespace/name is read as a pod, then as a service.
        const pod = podByKey.get().get(text);

        if (pod) return { type: "pod", endpoint: { type: "pod", pod }, pod };

        const service = allowService ? serviceByKey.get().get(text) : undefined;

        if (service) return { type: "service", service };

        return { type: "invalid", message: `"${text}" is not a pod, a service or an IP address` };
      };

      const source = computed(() => resolve(state.source.get(), false));
      const destination = computed(() => resolve(state.destination.get(), true));

      const dnsCheck = (from: Endpoint): FlowVerdict | undefined => {
        const dns = dnsPodsOf(pods.get())[0];

        return from.type === "pod" && dns ? evaluateFlow(model.get(), from, { type: "pod", pod: dns }, { port: 53, protocol: "UDP" }) : undefined;
      };

      const simulation = computed((): SimulationResult => {
        const from = source.get();
        const to = destination.get();

        if (from.type === "empty" || to.type === "empty") return { type: "incomplete", message: "Pick a source and a destination." };
        if (from.type === "invalid") return { type: "incomplete", message: from.message };
        if (to.type === "invalid") return { type: "incomplete", message: to.message };
        if (from.type === "service") return { type: "incomplete", message: "A service cannot start a flow." };

        if (to.type === "service") {
          const servicePort =
            to.service.ports.find((port) => String(port.port) === state.servicePort.get()) ??
            to.service.ports.find((port) => port.port === parsePort(state.port.get())) ??
            to.service.ports[0];

          if (!servicePort) return { type: "incomplete", message: `${to.service.name} exposes no ports.` };

          return {
            type: "service",
            source: from.endpoint,
            verdict: evaluateServiceFlow(model.get(), from.endpoint, to.service, servicePort, pods.get()),
            dns: dnsCheck(from.endpoint),
          };
        }

        const port = parsePort(state.port.get());

        if (port === undefined) return { type: "incomplete", message: "Enter a port between 1 and 65535." };
        if (from.type === "external" && to.type === "external") return { type: "incomplete", message: "At least one end has to be inside the cluster." };

        return { type: "flow", verdict: evaluateFlow(model.get(), from.endpoint, to.endpoint, { port, protocol: state.protocol.get() }) };
      });

      const endpointOptions = computed((): SearchOption[] =>
        [
          ...pods.get().map((pod) => ({
            value: `pod:${pod.namespace}/${pod.name}`,
            kind: pod.lab ? "Lab" : "Pod",
            name: pod.name,
            group: pod.namespace,
            detail: [
              pod.workload.kind === "Pod" ? undefined : `${pod.workload.kind} ${pod.workload.name}`,
              pod.ports.length > 0 ? `ports ${pod.ports.map((port) => `${port.port}/${port.protocol}`).join(", ")}` : undefined,
              pod.ips[0],
            ]
              .filter(Boolean)
              .join(" · "),
          })),
          ...services.get().map((service) => ({
            value: `svc:${service.namespace}/${service.name}`,
            kind: "Service",
            name: service.name,
            group: service.namespace,
            detail: [service.type, service.ports.map((port) => `${port.port}/${port.protocol}`).join(", "), service.clusterIps[0]].filter(Boolean).join(" · "),
          })),
        ].sort((a, b) => a.group.localeCompare(b.group) || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name)),
      );

      const matrixNamespaces = computed(() => {
        const chosen = [...state.matrixNamespaces];

        return chosen.length > 0 ? chosen : namespaces.get().filter((namespace) => !isSystemNamespace(namespace)).slice(0, 3);
      });

      const matrix = computed(() => {
        const chosen = new Set(matrixNamespaces.get());
        const all = groupByWorkload(pods.get().filter((pod) => chosen.has(pod.namespace) && !pod.hostNetwork));
        const groups = all.slice(0, matrixLimit);
        const port = parsePort(state.matrixPort.get());
        const ports: MatrixPorts =
          state.matrixPortMode.get() === "declared" || port === undefined
            ? { type: "declared" }
            : { type: "fixed", traffic: { port, protocol: state.matrixProtocol.get() as Protocol } };
        const current = model.get();
        const cells = reachabilityMatrix(current, groups, ports);
        const outside: Endpoint = { type: "external", ip: outsideIp };

        const fromOutside = groups.map((group) => {
          const pod = group.pods[0]!;
          const tried = ports.type === "fixed" ? [ports.traffic] : pod.ports.map((entry) => ({ port: entry.port, protocol: entry.protocol }));
          const allowed = tried.filter((traffic) => evaluateFlow(current, outside, { type: "pod", pod }, traffic).allowed).length;

          return { tried: tried.length, allowed };
        });

        const toOutside = groups.map((group) => {
          const traffic = ports.type === "fixed" ? ports.traffic : { port: 443, protocol: "TCP" as const };

          return evaluateFlow(current, { type: "pod", pod: group.pods[0]! }, outside, traffic).allowed;
        });

        return { groups, truncated: all.length - groups.length, cells, fromOutside, toOutside, ports };
      });

      const coverage = computed(() => {
        const shown = namespaces.get().filter((namespace) => !state.coverageHideSystem.get() || !isSystemNamespace(namespace));

        return coverageOf(model.get(), pods.get(), shown).sort(
          (a, b) => a.ingressIsolated / Math.max(a.pods, 1) - b.ingressIsolated / Math.max(b.pods, 1) || b.pods - a.pods,
        );
      });

      const policyList = computed(() => {
        const search = state.policySearch.get().trim().toLowerCase();
        const current = model.get();
        const livePods = pods.get();

        return current.policies
          .filter((policy) => !search || `${policy.ref.kind} ${policy.ref.namespace ?? ""} ${policy.ref.name} ${policy.selectorText}`.toLowerCase().includes(search))
          .map((policy) => ({ policy, selected: livePods.filter((pod) => policy.selects(pod, current.context)) }));
      });

      return {
        clusterId,
        state,
        snapshot,
        lab,
        labOverlay,
        isDraftPolicy,
        detection,
        model,
        pods,
        services,
        namespaces,
        source,
        destination,
        simulation,
        endpointOptions,
        matrixNamespaces,
        matrix,
        coverage,
        policyList,
        outsideIp,
      };
    };
  },
});

export type NetworkModelView = ReturnType<ReturnType<(typeof networkModelInjectable)["instantiate"]>>;
