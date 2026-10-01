import { getInjectable2 } from "@k8slens/injectable";
import { getPersistableValueInjectableBunch } from "@k8slens/persistable-contracts";

/** What the lab keeps of a cluster across restarts: the two editors, and the AI command if changed. */
export interface LabSaved {
  readonly drafts: string;
  readonly tests: string;
  readonly aiCommand: string;
}

export const labSavedBunch = getPersistableValueInjectableBunch<LabSaved, [clusterId: string]>()({
  id: "policy-lab",
  defaultValue: { instantiate: () => async () => ({ drafts: "", tests: "", aiCommand: "" }) },
});

/** Reads and writes a cluster's saved lab. A seam of its own so the views can be rendered without Lens. */
export const labPersistenceInjectable = getInjectable2({
  id: "real-governance-lab-persistence",

  instantiate: (di) => {
    const savedOf = di.inject(labSavedBunch.persistable);

    return () => ({
      load: async (clusterId: string): Promise<LabSaved> => (await savedOf(clusterId)).get(),
      save: async (clusterId: string, value: LabSaved) => (await savedOf(clusterId)).set(value),
    });
  },
});
