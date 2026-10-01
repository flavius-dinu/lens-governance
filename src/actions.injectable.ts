import { getInjectable2 } from "@k8slens/injectable";
import { getKubeResourceKind, getKubernetesApiVersion, kubeResourceInjectionToken } from "@k8slens/kubernetes-contracts";
import type { Subscribable } from "@k8slens/subscribable";
import { dump } from "js-yaml";
import { parseManifests } from "./engines/lab/manifests";
import { isPolicyDocument } from "./lab/lab-model.injectable";
import { labStateInjectable } from "./lab/lab-state.injectable";
import { openGovernanceViewInjectable } from "./navigation.injectable";
import { networkStateInjectable } from "./network/network-state.injectable";
import { policyStateInjectable } from "./policies/policy-state.injectable";
import { rbacStateInjectable } from "./rbac/rbac-state.injectable";

/** Opens the permissions view on one service account. */
export const inspectServiceAccountInjectable = getInjectable2({
  id: "real-governance-inspect-service-account",

  instantiate: (di) => {
    const rbacStateOf = di.inject(rbacStateInjectable);
    const openView = di.inject(openGovernanceViewInjectable)();

    return () => async (clusterId: string, namespace: string, name: string) => {
      rbacStateOf(clusterId).focusServiceAccount(namespace, name);
      await openView(clusterId, "rbac");
    };
  },
});

/** Opens the reachability simulator with a pod as the source. */
export const simulateFromPodInjectable = getInjectable2({
  id: "real-governance-simulate-from-pod",

  instantiate: (di) => {
    const networkStateOf = di.inject(networkStateInjectable);
    const openView = di.inject(openGovernanceViewInjectable)();

    return () => async (clusterId: string, namespace: string, name: string) => {
      networkStateOf(clusterId).simulateFrom(namespace, name);
      await openView(clusterId, "network");
    };
  },
});

/**
 * Opens the "what applies?" simulator on an existing resource. Its labels are read from the
 * cluster once, since a menu hands over the resource's identity rather than its content.
 */
export const simulatePoliciesForResourceInjectable = getInjectable2({
  id: "real-governance-simulate-policies-for-resource",
  consumptions: [kubeResourceInjectionToken],

  instantiate: (di) => {
    const policyStateOf = di.inject(policyStateInjectable);
    const openView = di.inject(openGovernanceViewInjectable)();
    const kubeResource = di.inject(kubeResourceInjectionToken)();

    const labelsOf = async (clusterId: string, kind: string, apiVersion: string, namespace: string | undefined, name: string) => {
      const resource = kubeResource(getKubeResourceKind(kind) as never, getKubernetesApiVersion(apiVersion) as never, clusterId, { name, namespace }) as unknown as Subscribable<
        { metadata?: { labels?: Record<string, string> } } | undefined
      >;
      const subscription = resource.subscribe();

      subscription.claim();

      try {
        return (await subscription.value).get()?.metadata?.labels ?? {};
      } catch {
        return {};
      } finally {
        subscription.dispose();
      }
    };

    return () => async (target: { clusterId: string; kind: string; apiVersion: string; namespace?: string; name: string }) => {
      const labels = await labelsOf(target.clusterId, target.kind, target.apiVersion, target.namespace, target.name);

      policyStateOf(target.clusterId).simulateResource(target.kind, target.namespace, target.name, labels);
      await openView(target.clusterId, "policies");
    };
  },
});

/* eslint-disable @typescript-eslint/no-explicit-any -- a resource of any kind */
type Json = any;

/** What the cluster writes on a resource, and a manifest leaves out. */
const asManifest = (resource: Json, kind: string, apiVersion: string) => {
  const { uid, resourceVersion, creationTimestamp, generation, managedFields, selfLink, ownerReferences, deletionTimestamp, ...metadata } = resource.metadata ?? {};
  const annotations = Object.fromEntries(
    Object.entries(metadata.annotations ?? {}).filter(([key]) => key !== "kubectl.kubernetes.io/last-applied-configuration" && key !== "deployment.kubernetes.io/revision"),
  );
  const { status, ...rest } = resource;

  return { ...rest, apiVersion, kind, metadata: { ...metadata, ...(Object.keys(annotations).length > 0 ? { annotations } : { annotations: undefined }) } };
};

/**
 * Copies a resource of the cluster into the policy lab, to change it as a draft or test against
 * it: a policy into the drafts, where it stands in for itself, anything else into the test manifests.
 */
export const copyToLabInjectable = getInjectable2({
  id: "real-governance-copy-to-lab",
  consumptions: [kubeResourceInjectionToken],

  instantiate: (di) => {
    const labStateOf = di.inject(labStateInjectable);
    const openView = di.inject(openGovernanceViewInjectable)();
    const kubeResource = di.inject(kubeResourceInjectionToken)();

    return () => async (target: { clusterId: string; kind: string; apiVersion: string; namespace?: string; name: string }) => {
      const subscribable = kubeResource(getKubeResourceKind(target.kind) as never, getKubernetesApiVersion(target.apiVersion) as never, target.clusterId, {
        name: target.name,
        namespace: target.namespace,
      }) as unknown as Subscribable<Json | undefined>;
      const subscription = subscribable.subscribe();

      subscription.claim();

      try {
        const resource = (await subscription.value).get();

        if (!resource) return;

        const yaml = dump(JSON.parse(JSON.stringify(asManifest(resource, target.kind, target.apiVersion))), { lineWidth: 140, noRefs: true });
        const lab = labStateOf(target.clusterId);
        const [document] = parseManifests(yaml, "drafts").documents;

        if (document && isPolicyDocument(document)) lab.appendDrafts(yaml);
        else lab.appendTests(yaml);

        await openView(target.clusterId, "lab");
      } finally {
        subscription.dispose();
      }
    };
  },
});
