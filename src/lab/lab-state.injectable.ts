import { getInjectable2 } from "@k8slens/injectable";
import { action, observable, reaction, runInAction } from "mobx";
import { labPersistenceInjectable } from "./lab-persistence.injectable";

export type AiRun =
  | { readonly status: "idle" }
  | { readonly status: "running"; readonly tool: string; readonly startedAt: number }
  | { readonly status: "done"; readonly tool: string; readonly yaml: string; readonly problems: readonly string[] }
  | { readonly status: "failed"; readonly tool: string; readonly error: string };

/** What the user has written in a cluster's policy lab. Kept across restarts, one per cluster. */
export const labStateInjectable = getInjectable2({
  id: "real-governance-lab-state",

  instantiate: (di) => {
    const persistence = di.inject(labPersistenceInjectable)();

    return (clusterId: string) => {
      const state = {
        drafts: observable.box(""),
        tests: observable.box(""),
        /** Whether the other views simulate with the drafts laid over the cluster. */
        applyDrafts: observable.box(true),
        aiRequest: observable.box(""),
        /** The user's own command for their AI tool, when the one Lens's selection suggests does not suit. */
        aiCommand: observable.box(""),
        aiRun: observable.box<AiRun>({ status: "idle" }, { deep: false }),
        showAiSettings: observable.box(false),
        /** Restored from disk: until then, nothing is written back, so an early save cannot erase the saved lab. */
        restored: observable.box(false),
      };

      void persistence
        .load(clusterId)
        .then((saved) =>
          runInAction(() => {
            // What was typed before the saved lab arrived wins over it.
            if (!state.drafts.get()) state.drafts.set(saved.drafts);
            if (!state.tests.get()) state.tests.set(saved.tests);
            if (!state.aiCommand.get()) state.aiCommand.set(saved.aiCommand);
          }),
        )
        .catch(() => undefined)
        .finally(() => runInAction(() => state.restored.set(true)));

      reaction(
        () => ({ restored: state.restored.get(), drafts: state.drafts.get(), tests: state.tests.get(), aiCommand: state.aiCommand.get() }),
        ({ restored, ...value }) => {
          if (restored) void persistence.save(clusterId, value).catch(() => undefined);
        },
        { delay: 500 },
      );

      return {
        ...state,
        setDrafts: action((value: string) => state.drafts.set(value)),
        setTests: action((value: string) => state.tests.set(value)),
        setApplyDrafts: action((value: boolean) => state.applyDrafts.set(value)),
        setAiRequest: action((value: string) => state.aiRequest.set(value)),
        setAiCommand: action((value: string) => state.aiCommand.set(value)),
        setAiRun: action((run: AiRun) => state.aiRun.set(run)),
        setShowAiSettings: action((value: boolean) => state.showAiSettings.set(value)),

        /** Adds manifests after what is there, as a separate document. */
        appendDrafts: action((yaml: string) => {
          const current = state.drafts.get().trimEnd();

          state.drafts.set(current ? `${current}\n---\n${yaml.trim()}\n` : `${yaml.trim()}\n`);
        }),
        appendTests: action((yaml: string) => {
          const current = state.tests.get().trimEnd();

          state.tests.set(current ? `${current}\n---\n${yaml.trim()}\n` : `${yaml.trim()}\n`);
        }),
      };
    };
  },
});

export type LabState = ReturnType<ReturnType<(typeof labStateInjectable)["instantiate"]>>;
