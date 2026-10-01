import { effectiveAiToolDisplayNameInjectionToken, effectiveAiToolKindInjectionToken, noAiToolKind, shellQuote } from "@k8slens/ai-tools-contracts";
import { askAiInjectionToken } from "@k8slens/ask-ai-contracts";
import { runCliCommandInjectionToken } from "@k8slens/cli-contracts";
import { getInjectable2 } from "@k8slens/injectable";
import { computed, type IComputedValue, observable, runInAction } from "mobx";
import { parseManifests } from "../engines/lab/manifests";
import { buildAskAiContext, buildGenerationPrompt, commandLineFor, extractYaml, headlessCommandFor, type LabBrief } from "../engines/lab/prompt";
import { labStateInjectable } from "./lab-state.injectable";

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

export interface AiTool {
  /** What the user calls it, as Lens names it. */
  readonly name: string;
  /** The command that asks it one question, or undefined when the lab does not know one. */
  readonly command?: string;
  /** Whether the command is the user's own rather than the one the lab suggests. */
  readonly custom: boolean;
}

/**
 * The AI behind the lab. Lens hands an extension no AI answers of its own, so the lab asks the AI
 * tool the user has selected in Lens through its command line, and reads the YAML it prints. Ask
 * AI is the other route: it opens Lens's assistant, briefed, and the user brings the YAML back.
 */
export const labAiInjectable = getInjectable2({
  id: "real-governance-lab-ai",
  consumptions: [runCliCommandInjectionToken, askAiInjectionToken, effectiveAiToolKindInjectionToken, effectiveAiToolDisplayNameInjectionToken],

  instantiate: (di) => {
    const runCliCommand = di.inject(runCliCommandInjectionToken)();
    const askAi = di.inject(askAiInjectionToken)();
    const labStateOf = di.inject(labStateInjectable);
    const selection = observable.box<{ kind: IComputedValue<string>; name: IComputedValue<string> } | undefined>(undefined, { deep: false });

    void Promise.all([di.inject(effectiveAiToolKindInjectionToken)(), di.inject(effectiveAiToolDisplayNameInjectionToken)()])
      .then(([kind, name]) => runInAction(() => selection.set({ kind, name })))
      .catch(() => undefined);

    return () => {
      const toolFor = (clusterId: string) =>
        computed((): AiTool | undefined => {
          const own = labStateOf(clusterId).aiCommand.get().trim();
          const selected = selection.get();
          const kind = selected?.kind.get();
          const name = kind && kind !== noAiToolKind ? selected!.name.get() : undefined;

          if (own) return { name: name ?? "your AI tool", command: own, custom: true };
          if (!name) return undefined;

          return { name, command: headlessCommandFor(kind!, name), custom: false };
        });

      return {
        toolFor,

        /** Asks the selected tool for manifests, and keeps its answer for the user to review. */
        generate: async (clusterId: string, brief: LabBrief) => {
          const state = labStateOf(clusterId);
          const tool = toolFor(clusterId).get();

          if (!tool?.command) return;

          state.setAiRun({ status: "running", tool: tool.name, startedAt: Date.now() });

          try {
            const output = await runCliCommand(commandLineFor(tool.command, shellQuote(buildGenerationPrompt(brief))));
            const yaml = extractYaml(output);
            const parsed = parseManifests(yaml, "drafts");
            const problems = [
              ...parsed.errors.map((error) => `Line ${error.line}: ${error.message}`),
              ...(parsed.documents.length === 0 && parsed.errors.length === 0 ? [`${tool.name} answered without a manifest.`] : []),
            ];

            state.setAiRun({ status: "done", tool: tool.name, yaml: yaml || output.trim(), problems });
          } catch (error) {
            state.setAiRun({ status: "failed", tool: tool.name, error: messageOf(error) });
          }
        },

        /** Opens Lens's Ask AI on the request, briefed on the cluster and the lab. */
        ask: (clusterId: string, brief: LabBrief) =>
          askAi({
            clusterId,
            prompt: brief.request.trim() ? `Write this policy for my cluster's policy lab: ${brief.request.trim()}` : undefined,
            context: buildAskAiContext(brief),
          }),
      };
    };
  },
});
