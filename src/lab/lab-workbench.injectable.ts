import { getInjectable2 } from "@k8slens/injectable";
import { computed } from "mobx";
import { clusterLabelInjectable } from "../cluster-label.injectable";
import { type LabDocument } from "../engines/lab/manifests";
import type { ClusterBrief, LabBrief } from "../engines/lab/prompt";
import { evaluateFlow, groupByWorkload, policiesSelecting } from "../engines/net/evaluate";
import { netPolicyRefKey, type PodInfo } from "../engines/net/model";
import { policyRefKey } from "../engines/policies/model";
import { openGovernanceViewInjectable } from "../navigation.injectable";
import { networkModelInjectable } from "../network/network-model.injectable";
import { policyModelInjectable } from "../policies/policy-model.injectable";
import { labAiInjectable } from "./lab-ai.injectable";
import { isPolicyDocument, labModelInjectable } from "./lab-model.injectable";

/* eslint-disable @typescript-eslint/no-explicit-any -- manifests are open-ended YAML */
type Json = any;

const roleLabel: Record<LabDocument["role"], string> = {
  "network-policy": "network policy",
  "admission-policy": "admission policy",
  "policy-exception": "policy exception",
  "constraint-template": "constraint template",
  constraint: "constraint",
  namespace: "namespace",
  workload: "workload",
  service: "service",
  resource: "resource",
};

export const describeRole = (document: LabDocument) => roleLabel[document.role];

/** The most existing pods each draft admission policy is tried against. */
const impactLimit = 400;

/** How far a test workload reaches, and who reaches it, on the network. */
export interface WorkloadReach {
  readonly document: LabDocument;
  readonly pod?: PodInfo;
  readonly ingressPolicies: readonly string[];
  readonly egressPolicies: readonly string[];
  readonly draftsSelecting: readonly string[];
  /** Of the cluster's other workloads, how many may open its first declared port. */
  readonly inbound?: { readonly port: number; readonly protocol: string; readonly allowed: number; readonly of: number; readonly examples: readonly string[] };
  readonly toOutside: boolean;
  readonly toDns?: boolean;
}

/** One draft admission rule tried against the pods the cluster already runs. */
export interface DraftImpact {
  readonly policy: string;
  readonly rule: string;
  readonly effect: string;
  readonly tried: number;
  readonly failing: readonly { readonly pod: string; readonly detail: string }[];
  readonly unknown: number;
}

/** Everything the policy lab shows for a cluster, worked out from the lab and the other views' models. */
export const labWorkbenchInjectable = getInjectable2({
  id: "real-governance-lab-workbench",

  instantiate: (di) => {
    const labOf = di.inject(labModelInjectable);
    const networkOf = di.inject(networkModelInjectable);
    const policiesOf = di.inject(policyModelInjectable);
    const clusterLabelOf = di.inject(clusterLabelInjectable);
    const ai = di.inject(labAiInjectable)();
    const openView = di.inject(openGovernanceViewInjectable)();

    return (clusterId: string) => {
      const lab = labOf(clusterId);
      const network = networkOf(clusterId);
      const policies = policiesOf(clusterId);
      const tool = ai.toolFor(clusterId);

      /** Each test resource, as admission would take it. */
      const admission = computed(() =>
        lab.resources.get().map((document) => ({ document, ...policies.checkDocument(document) })),
      );

      const reach = computed((): WorkloadReach[] => {
        const model = network.model.get();
        const pods = network.pods.get();
        const groups = groupByWorkload(pods.filter((pod) => !pod.lab && !pod.hostNetwork));
        const dns = pods.find((pod) => pod.labels["k8s-app"] === "kube-dns");

        return lab.resources
          .get()
          .filter((document) => document.role === "workload")
          .map((document) => {
            const pod = pods.find((candidate) => candidate.lab && candidate.namespace === document.namespace && candidate.name === document.name);

            if (!pod) return { document, ingressPolicies: [], egressPolicies: [], draftsSelecting: [], toOutside: false };

            const selecting = policiesSelecting(model, pod);
            const label = (policy: (typeof model.policies)[number]) => `${policy.ref.kind} ${policy.ref.namespace ? `${policy.ref.namespace}/` : ""}${policy.ref.name}`;
            const port = pod.ports[0];
            const inbound = port
              ? (() => {
                  const results = groups.map((group) => ({
                    group,
                    allowed: evaluateFlow(model, { type: "pod", pod: group.pods[0]! }, { type: "pod", pod }, { port: port.port, protocol: port.protocol }).allowed,
                  }));

                  return {
                    port: port.port,
                    protocol: port.protocol,
                    allowed: results.filter((result) => result.allowed).length,
                    of: results.length,
                    examples: results.filter((result) => result.allowed).slice(0, 5).map((result) => `${result.group.namespace}/${result.group.name}`),
                  };
                })()
              : undefined;

            return {
              document,
              pod,
              ingressPolicies: selecting.ingress.map(label),
              egressPolicies: selecting.egress.map(label),
              draftsSelecting: [...selecting.ingress, ...selecting.egress].filter((policy) => network.isDraftPolicy(policy.ref)).map(label),
              inbound,
              toOutside: evaluateFlow(model, { type: "pod", pod }, { type: "external", ip: network.outsideIp }, { port: 443, protocol: "TCP" }).allowed,
              toDns: dns ? evaluateFlow(model, { type: "pod", pod }, { type: "pod", pod: dns }, { port: 53, protocol: "UDP" }).allowed : undefined,
            };
          });
      });

      /** The pods each draft network policy selects, cluster pods and lab ones alike. */
      const networkDrafts = computed(() =>
        network.policyList
          .get()
          .filter(({ policy }) => network.isDraftPolicy(policy.ref))
          .map(({ policy, selected }) => ({ key: `${netPolicyRefKey(policy.ref)}/${policy.direction}`, policy, selected })),
      );

      /** Draft admission rules tried against the pods already running: what would start failing. */
      const admissionImpact = computed((): DraftImpact[] => {
        const draftRules = policies.entries
          .get()
          .filter((entry) => policies.isDraftPolicy(entry.policy.ref))
          // Running pods are pods: the rules Kyverno writes out for their controllers never meet one.
          .flatMap((entry) => entry.policy.rules.filter((rule) => !rule.autogen).map((rule) => ({ entry, rule })));

        if (draftRules.length === 0) return [];

        const running = (network.snapshot.get().items.pods as Json[]).slice(0, impactLimit);
        const byRule = new Map<string, { policy: string; rule: string; effect: string; tried: number; failing: { pod: string; detail: string }[]; unknown: number }>();

        for (const { entry, rule } of draftRules) {
          byRule.set(rule.id, { policy: entry.policy.title, rule: rule.name, effect: rule.effect, tried: 0, failing: [], unknown: 0 });
        }

        for (const raw of running) {
          const document: LabDocument = {
            id: `cluster:${raw.metadata.uid}`,
            source: "tests",
            line: 0,
            role: "workload",
            kind: "Pod",
            apiVersion: "v1",
            group: "",
            name: raw.metadata.name,
            namespace: raw.metadata.namespace,
            raw: { apiVersion: "v1", kind: "Pod", ...raw },
            problems: [],
          };

          for (const checked of policies.checkDocument(document, "CREATE", (policy) => policies.isDraftPolicy(policy.ref)).checked) {
            const impact = byRule.get(checked.rule.id);

            if (!impact) continue;

            impact.tried++;

            if (checked.check.status === "fail") impact.failing.push({ pod: `${document.namespace}/${document.name}`, detail: checked.check.detail });
            if (checked.check.status === "unknown") impact.unknown++;
          }
        }

        return [...byRule.values()];
      });

      const counts = computed(() => {
        const documents = lab.documents.get();

        return {
          drafts: documents.filter(isPolicyDocument).length,
          tests: documents.length - documents.filter(isPolicyDocument).length,
          errors: lab.parsed.get().errors.length,
        };
      });

      const clusterBrief = (): ClusterBrief => {
        const detection = network.detection.get();
        const installed = policies.installed.get();
        const namespaceItems = network.snapshot.get().items.namespaces as Json[];

        return {
          clusterName: clusterLabelOf(clusterId).get(),
          network: `${detection.mode === "kubernetes" ? "Kubernetes NetworkPolicy" : detection.mode === "cilium" ? "Cilium" : "Calico"}${detection.cni ? ` (CNI: ${detection.cni})` : ""}`,
          admissionEngines: [installed.kyverno ? "Kyverno" : "", installed.kyvernoCel ? "Kyverno CEL policies" : "", installed.gatekeeper ? "OPA Gatekeeper" : ""].filter(Boolean),
          namespaces: namespaceItems.map((namespace) => ({ name: namespace.metadata.name, labels: namespace.metadata.labels ?? {} })),
          workloads: groupByWorkload(network.pods.get().filter((pod) => !pod.lab)).map((group) => ({
            namespace: group.namespace,
            kind: group.kind,
            name: group.name,
            labels: group.pods[0]!.labels,
            ports: group.pods[0]!.ports.map((port) => `${port.port}/${port.protocol}`),
          })),
          policies: [
            ...new Set([
              ...network.model.get().policies.filter((policy) => !network.isDraftPolicy(policy.ref)).map((policy) => `${policy.ref.kind} ${policy.ref.namespace ? `${policy.ref.namespace}/` : ""}${policy.ref.name}`),
              ...policies.entries
                .get()
                .filter((entry) => !policies.isDraftPolicy(entry.policy.ref))
                .map((entry) => `${entry.policy.ref.kind} ${entry.policy.ref.namespace ? `${entry.policy.ref.namespace}/` : ""}${entry.policy.ref.name}: ${entry.policy.title}`),
            ]),
          ],
        };
      };

      const brief = (): LabBrief => ({ request: lab.state.aiRequest.get(), cluster: clusterBrief(), drafts: lab.state.drafts.get(), tests: lab.state.tests.get() });

      return {
        clusterId,
        lab,
        state: lab.state,
        network,
        policies,
        tool,
        admission,
        reach,
        networkDrafts,
        admissionImpact,
        counts,
        policyKeyOf: policyRefKey,

        generate: () => ai.generate(clusterId, brief()),
        askAi: () => ai.ask(clusterId, brief()),

        /** Takes the generated YAML into the lab, after or instead of the drafts there. */
        acceptGenerated: (mode: "add" | "replace") => {
          const run = lab.state.aiRun.get();

          if (run.status !== "done") return;

          if (mode === "replace") lab.state.setDrafts(`${run.yaml.trim()}\n`);
          else lab.state.appendDrafts(run.yaml);

          lab.state.setAiRun({ status: "idle" });
        },
        discardGenerated: () => lab.state.setAiRun({ status: "idle" }),

        /** Opens the reachability simulator on a test workload, as the destination. */
        simulateTo: async (document: LabDocument) => {
          const pod = reach.get().find((entry) => entry.document.id === document.id)?.pod;

          network.state.simulateBetween("", `pod:${document.namespace}/${document.name}`, pod?.ports[0]?.port, pod?.ports[0]?.protocol);
          await openView(clusterId, "network");
        },
        simulateFrom: async (document: LabDocument) => {
          network.state.simulateFrom(document.namespace ?? "default", document.name);
          await openView(clusterId, "network");
        },
      };
    };
  },
});

export type LabWorkbench = ReturnType<ReturnType<(typeof labWorkbenchInjectable)["instantiate"]>>;
