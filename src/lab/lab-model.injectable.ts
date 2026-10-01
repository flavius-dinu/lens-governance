import { getInjectable2 } from "@k8slens/injectable";
import { computed } from "mobx";
import { type LabDocument, type ParseError, parseManifests, podOfWorkload } from "../engines/lab/manifests";
import { withAutogenRules } from "../engines/policies/kyverno";
import { labStateInjectable } from "./lab-state.injectable";

/* eslint-disable @typescript-eslint/no-explicit-any -- manifests are open-ended YAML */
type Json = any;

/**
 * What the lab adds to a cluster, sorted by the engine that reads it. Each list holds resources as
 * the cluster would list them, so a view lays them over its own.
 */
export interface LabOverlay {
  readonly active: boolean;
  readonly networkPolicies: readonly Json[];
  readonly ciliumPolicies: readonly Json[];
  readonly calicoPolicies: readonly Json[];
  readonly calicoTiers: readonly Json[];
  readonly namespaces: readonly Json[];
  /** One stand-in pod per workload, without an IP. */
  readonly pods: readonly Json[];
  readonly services: readonly Json[];
  readonly kyvernoPolicies: readonly Json[];
  readonly kyvernoCelPolicies: readonly Json[];
  readonly kyvernoExceptions: readonly Json[];
  readonly kyvernoCelExceptions: readonly Json[];
  readonly constraintTemplates: readonly Json[];
  readonly constraints: readonly Json[];
}

const empty: LabOverlay = {
  active: false,
  networkPolicies: [],
  ciliumPolicies: [],
  calicoPolicies: [],
  calicoTiers: [],
  namespaces: [],
  pods: [],
  services: [],
  kyvernoPolicies: [],
  kyvernoCelPolicies: [],
  kyvernoExceptions: [],
  kyvernoCelExceptions: [],
  constraintTemplates: [],
  constraints: [],
};

const policyRoles = new Set(["network-policy", "admission-policy", "policy-exception", "constraint-template", "constraint"]);

export const isPolicyDocument = (document: LabDocument) => policyRoles.has(document.role);

/** Lab pods are told from the cluster's by their uid. */
export const isLabUid = (uid: string) => uid.startsWith("lab:");

/** A cluster's policy lab: the drafts and test manifests, read, and what they add to the other views. */
export const labModelInjectable = getInjectable2({
  id: "real-governance-lab-model",

  instantiate: (di) => {
    const stateOf = di.inject(labStateInjectable);

    return (clusterId: string) => {
      const state = stateOf(clusterId);

      const parsed = computed(() => {
        const drafts = parseManifests(state.drafts.get(), "drafts");
        const tests = parseManifests(state.tests.get(), "tests");

        return { documents: [...drafts.documents, ...tests.documents], errors: [...drafts.errors, ...tests.errors] as ParseError[] };
      });

      const documents = computed(() => parsed.get().documents);
      const policies = computed(() => documents.get().filter(isPolicyDocument));
      const resources = computed(() => documents.get().filter((document) => !isPolicyDocument(document)));

      const overlay = computed((): LabOverlay => {
        if (!state.applyDrafts.get() || documents.get().length === 0) return empty;

        const all = documents.get();
        const of = (test: (document: LabDocument) => boolean) => all.filter(test).map((document) => document.raw);

        return {
          active: true,
          networkPolicies: of((document) => document.netFlavour === "kubernetes"),
          ciliumPolicies: of((document) => document.netFlavour === "cilium"),
          calicoPolicies: of((document) => document.netFlavour === "calico"),
          calicoTiers: of((document) => document.netFlavour === "calico-tier"),
          namespaces: of((document) => document.role === "namespace"),
          pods: all.filter((document) => document.role === "workload").flatMap((document) => podOfWorkload(document) ?? []),
          services: of((document) => document.role === "service"),
          kyvernoPolicies: of((document) => document.role === "admission-policy" && document.group === "kyverno.io").map(withAutogenRules),
          kyvernoCelPolicies: of((document) => document.role === "admission-policy" && document.group === "policies.kyverno.io"),
          kyvernoExceptions: of((document) => document.role === "policy-exception" && document.group === "kyverno.io"),
          kyvernoCelExceptions: of((document) => document.role === "policy-exception" && document.group === "policies.kyverno.io"),
          constraintTemplates: of((document) => document.role === "constraint-template"),
          constraints: of((document) => document.role === "constraint"),
        };
      });

      /** The identities of the draft policies, for marking them wherever they are listed. */
      const draftKeys = computed(() => new Set(overlay.get().active ? policies.get().map((document) => `${document.kind}|${document.namespace ?? ""}|${document.name}`) : []));

      return {
        clusterId,
        state,
        parsed,
        documents,
        policies,
        resources,
        overlay,
        isDraft: (kind: string, namespace: string | undefined, name: string) => draftKeys.get().has(`${kind}|${namespace ?? ""}|${name}`),
      };
    };
  },
});

export type LabModel = ReturnType<ReturnType<(typeof labModelInjectable)["instantiate"]>>;
