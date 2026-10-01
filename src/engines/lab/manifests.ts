/**
 * Manifests pasted into the policy lab: read from YAML, told apart by what they are (a policy to
 * try, a resource to test against the policies), and turned into what the engines read.
 */

import { load } from "js-yaml";
import { kindInfo } from "../policies/model";

/* eslint-disable @typescript-eslint/no-explicit-any -- manifests are open-ended YAML */
type Json = any;

export type LabRole =
  /** NetworkPolicy, CiliumNetworkPolicy, Calico's policies and tiers. */
  | "network-policy"
  /** Kyverno ClusterPolicy, Policy, ValidatingPolicy. */
  | "admission-policy"
  | "policy-exception"
  | "constraint-template"
  | "constraint"
  | "namespace"
  /** Something that runs pods: a Pod, Deployment, Job, … */
  | "workload"
  | "service"
  /** Any other resource, tested against admission policies only. */
  | "resource";

export type NetFlavour = "kubernetes" | "cilium" | "calico" | "calico-tier";

export interface LabDocument {
  /** Unique among the lab's documents: which editor, and the document's place in it. */
  readonly id: string;
  readonly source: "drafts" | "tests";
  /** The line the document starts on, from 1. */
  readonly line: number;
  readonly role: LabRole;
  readonly kind: string;
  readonly apiVersion: string;
  readonly group: string;
  readonly name: string;
  readonly namespace?: string;
  /** The resource as written, with the namespace filled in where the cluster would default it. */
  readonly raw: Json;
  readonly netFlavour?: NetFlavour;
  /** What is wrong with it, short of not being YAML at all. */
  readonly problems: readonly string[];
}

export interface ParseError {
  readonly source: "drafts" | "tests";
  readonly line: number;
  readonly message: string;
}

export interface ParsedManifests {
  readonly documents: readonly LabDocument[];
  readonly errors: readonly ParseError[];
}

const podControllers = new Set(["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob"]);

const groupOf = (apiVersion: string) => (apiVersion.includes("/") ? apiVersion.slice(0, apiVersion.lastIndexOf("/")) : "");

const classify = (kind: string, group: string): { role: LabRole; netFlavour?: NetFlavour } => {
  if (group === "networking.k8s.io" && kind === "NetworkPolicy") return { role: "network-policy", netFlavour: "kubernetes" };
  if (group === "cilium.io" && (kind === "CiliumNetworkPolicy" || kind === "CiliumClusterwideNetworkPolicy")) return { role: "network-policy", netFlavour: "cilium" };

  if (group === "projectcalico.org" || group === "crd.projectcalico.org") {
    if (kind === "NetworkPolicy" || kind === "GlobalNetworkPolicy") return { role: "network-policy", netFlavour: "calico" };
    if (kind === "Tier") return { role: "network-policy", netFlavour: "calico-tier" };
  }

  if (group === "kyverno.io" && (kind === "ClusterPolicy" || kind === "Policy")) return { role: "admission-policy" };
  if (group === "policies.kyverno.io" && (kind === "ValidatingPolicy" || kind === "NamespacedValidatingPolicy")) return { role: "admission-policy" };
  if ((group === "kyverno.io" || group === "policies.kyverno.io") && kind === "PolicyException") return { role: "policy-exception" };
  if (group === "templates.gatekeeper.sh" && kind === "ConstraintTemplate") return { role: "constraint-template" };
  if (group === "constraints.gatekeeper.sh") return { role: "constraint" };
  if (group === "" && kind === "Namespace") return { role: "namespace" };
  if (group === "" && kind === "Service") return { role: "service" };
  if ((group === "" && kind === "Pod") || podControllers.has(kind)) return { role: "workload" };

  return { role: "resource" };
};

/** Kinds that live outside namespaces, beyond the ones the simulation knows. */
const clusterScoped = new Set([
  "ClusterPolicy",
  "ValidatingPolicy",
  "CiliumClusterwideNetworkPolicy",
  "GlobalNetworkPolicy",
  "Tier",
  "ConstraintTemplate",
  "Namespace",
  "Node",
  "ClusterRole",
  "ClusterRoleBinding",
  "PersistentVolume",
  "StorageClass",
  "CustomResourceDefinition",
]);

const isNamespaced = (kind: string, role: LabRole) => role !== "constraint" && !clusterScoped.has(kind) && kindInfo(kind).namespaced;

/** Splits on `---` lines, so one broken document does not hide the others. */
const splitDocuments = (text: string) => {
  const chunks: { line: number; text: string }[] = [];
  let start = 0;
  let current: string[] = [];

  text.split("\n").forEach((line, index) => {
    if (/^---(\s|$)/.test(line)) {
      chunks.push({ line: start + 1, text: current.join("\n") });
      start = index + 1;
      current = [];
    } else {
      current.push(line);
    }
  });
  chunks.push({ line: start + 1, text: current.join("\n") });

  return chunks.filter((chunk) => chunk.text.split("\n").some((line) => line.trim() && !line.trim().startsWith("#")));
};

export const parseManifests = (text: string, source: "drafts" | "tests"): ParsedManifests => {
  const documents: LabDocument[] = [];
  const errors: ParseError[] = [];

  for (const chunk of splitDocuments(text)) {
    let value: Json;

    try {
      value = load(chunk.text);
    } catch (error) {
      const mark = (error as { mark?: { line?: number } }).mark;
      const reason = (error as { reason?: string }).reason ?? (error as Error).message;

      // An unclosed document is reported past its end: keep the line within the document.
      const lastLine = chunk.line + chunk.text.trimEnd().split("\n").length - 1;

      errors.push({ source, line: Math.min(chunk.line + (mark?.line ?? 0), lastLine), message: `Not valid YAML: ${reason}` });
      continue;
    }

    const items: Json[] = value?.kind === "List" && Array.isArray(value.items) ? value.items : [value];

    for (const item of items) {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        errors.push({ source, line: chunk.line, message: "Not a Kubernetes resource: a document has to be a map with apiVersion and kind." });
        continue;
      }

      if (typeof item.kind !== "string" || typeof item.apiVersion !== "string") {
        errors.push({ source, line: chunk.line, message: "Not a Kubernetes resource: apiVersion and kind are missing." });
        continue;
      }

      const group = groupOf(item.apiVersion);
      const { role, netFlavour } = classify(item.kind, group);
      const problems: string[] = [];
      const name = typeof item.metadata?.name === "string" && item.metadata.name ? item.metadata.name : `unnamed-${documents.length + 1}`;

      if (name !== item.metadata?.name) problems.push("has no metadata.name");

      const namespaced = isNamespaced(item.kind, role);
      const namespace = namespaced ? (item.metadata?.namespace ?? "default") : undefined;
      const raw = { ...item, metadata: { ...(item.metadata ?? {}), name, ...(namespace ? { namespace } : {}) } };

      documents.push({
        id: `${source}:${documents.length}`,
        source,
        line: chunk.line,
        role,
        kind: item.kind,
        apiVersion: item.apiVersion,
        group,
        name,
        namespace,
        raw,
        netFlavour,
        problems,
      });
    }
  }

  return { documents, errors };
};

/** The pod template of a workload: what its pods will look like. */
export const podTemplateOf = (resource: Json): Json | undefined => {
  if (resource.kind === "Pod") return { metadata: resource.metadata, spec: resource.spec };
  if (resource.kind === "CronJob") return resource.spec?.jobTemplate?.spec?.template;

  return resource.spec?.template;
};

/**
 * A pod as the network engine reads one, standing for the pods a workload would run. It has no IP
 * yet, so rules that match by address cannot select it.
 */
export const podOfWorkload = (document: LabDocument): Json | undefined => {
  const template = podTemplateOf(document.raw);

  if (!template) return undefined;

  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      ...(template.metadata ?? {}),
      name: document.name,
      namespace: document.namespace ?? "default",
      uid: `lab:${document.kind}/${document.namespace}/${document.name}`,
      labels: template.metadata?.labels ?? {},
    },
    spec: template.spec ?? {},
    status: { phase: "Pending" },
  };
};

/** The identity the cluster knows a resource by: a draft with the same one stands in for it. */
export const identityOf = (resource: Json) => `${resource?.kind}|${resource?.metadata?.namespace ?? ""}|${resource?.metadata?.name}`;

/** The cluster's resources with the drafts laid over them: a draft replaces the one it shares an identity with. */
export const overlay = <T>(cluster: readonly T[], drafts: readonly T[], withKind: (item: T) => T = (item) => item): T[] => {
  const replaced = new Set(drafts.map((item) => identityOf(withKind(item))));

  return [...cluster.filter((item) => !replaced.has(identityOf(withKind(item)))), ...drafts];
};
