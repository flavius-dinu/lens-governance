/**
 * What the lab tells an AI tool when it asks for a policy: the request, what the cluster runs, and
 * what is in the lab already. Kept to plain text so the same briefing serves a command-line tool
 * and Lens's Ask AI alike.
 */

export interface ClusterBrief {
  readonly clusterName: string;
  /** Which network semantics apply, and the CNI if known. */
  readonly network: string;
  readonly admissionEngines: readonly string[];
  readonly namespaces: readonly { readonly name: string; readonly labels: Readonly<Record<string, string>> }[];
  readonly workloads: readonly { readonly namespace: string; readonly kind: string; readonly name: string; readonly labels: Readonly<Record<string, string>>; readonly ports: readonly string[] }[];
  readonly policies: readonly string[];
}

export interface LabBrief {
  readonly request: string;
  readonly cluster: ClusterBrief;
  readonly drafts: string;
  readonly tests: string;
}

/** Shell arguments have a ceiling; what does not fit is summarised away rather than cut mid-line. */
const budget = 60_000;

const clip = (text: string, limit: number) => (text.length <= limit ? text : `${text.slice(0, text.lastIndexOf("\n", limit))}\n# … ${text.length - limit} more characters left out`);

const labelsText = (labels: Readonly<Record<string, string>>) =>
  Object.entries(labels)
    .filter(([key]) => !key.startsWith("pod-template-") && key !== "controller-revision-hash")
    .map(([key, value]) => `${key}=${value}`)
    .join(", ");

export const describeCluster = (cluster: ClusterBrief) =>
  [
    `Cluster: ${cluster.clusterName}`,
    `Network policies are evaluated with ${cluster.network} semantics.`,
    `Admission engines installed: ${cluster.admissionEngines.length > 0 ? cluster.admissionEngines.join(", ") : "none detected"}.`,
    "",
    "Namespaces (name: labels):",
    ...cluster.namespaces.slice(0, 80).map((namespace) => `- ${namespace.name}: ${labelsText(namespace.labels) || "(no labels)"}`),
    "",
    "Workloads (namespace/kind/name: pod labels; container ports):",
    ...cluster.workloads.slice(0, 120).map((workload) => `- ${workload.namespace}/${workload.kind}/${workload.name}: ${labelsText(workload.labels) || "(no labels)"}; ${workload.ports.join(", ") || "no ports"}`),
    "",
    "Policies already in the cluster:",
    ...(cluster.policies.length > 0 ? cluster.policies.slice(0, 150).map((policy) => `- ${policy}`) : ["- none"]),
  ].join("\n");

const rules = [
  "You write Kubernetes policy manifests for a policy lab that simulates them against a live cluster before anyone applies them.",
  "Answer with YAML only: one or more complete Kubernetes manifests separated by lines of ---. No prose, no Markdown, no code fences.",
  "Use the policy kinds this cluster can enforce: NetworkPolicy (networking.k8s.io/v1), CiliumNetworkPolicy or Calico policies when that CNI runs, Kyverno ClusterPolicy or Policy (kyverno.io/v1) when Kyverno is installed, Gatekeeper constraints when Gatekeeper is.",
  "Select pods by the labels the workloads below actually carry, and namespaces by their kubernetes.io/metadata.name label.",
  "Prefer Kyverno validate rules written as patterns (with anchors, wildcards and operators) over CEL or JMESPath, so the lab can check them offline.",
  "Give every policy a descriptive metadata.name, and for Kyverno a policies.kyverno.io/title and description annotation.",
  "If the request also asks for a workload to test with, add it after the policies.",
  "Do not run commands or use tools: answer from what is written here.",
];

export const buildGenerationPrompt = (brief: LabBrief) => {
  const drafts = brief.drafts.trim() ? clip(brief.drafts, 12_000) : "(none)";
  const tests = brief.tests.trim() ? clip(brief.tests, 8_000) : "(none)";
  const head = [...rules, "", "What to write:", brief.request.trim(), ""].join("\n");
  const tail = ["", "Draft policies already in the lab (keep, extend or replace them as the request says):", drafts, "", "Test manifests in the lab:", tests].join("\n");

  return `${head}\n${clip(describeCluster(brief.cluster), budget - head.length - tail.length)}\n${tail}`;
};

/** What Ask AI is told before the conversation starts; the question is the user's own request. */
export const buildAskAiContext = (brief: LabBrief) =>
  [
    "The user is in the Policy lab of the real-governance Lens extension: they draft policies and test manifests there and see what the cluster would do with them before applying anything.",
    "Write the policy they ask for as YAML they can paste into the lab's draft policies. Prefer Kyverno patterns to CEL or JMESPath, since the lab checks patterns offline.",
    "",
    "## What the cluster runs",
    "",
    clip(describeCluster(brief.cluster), 30_000),
    "",
    "## Draft policies in the lab",
    "",
    "```yaml",
    brief.drafts.trim() ? clip(brief.drafts, 12_000) : "# none",
    "```",
    "",
    "## Test manifests in the lab",
    "",
    "```yaml",
    brief.tests.trim() ? clip(brief.tests, 8_000) : "# none",
    "```",
  ].join("\n");

/**
 * The YAML in an answer: the contents of its fenced blocks if it has any, otherwise the answer from
 * its first line that looks like a manifest.
 */
export const extractYaml = (answer: string): string => {
  const fenced = [...answer.matchAll(/```(?:ya?ml|yml)?[ \t]*\n([\s\S]*?)```/g)].map((match) => match[1]!.trim()).filter(Boolean);

  if (fenced.length > 0) return fenced.join("\n---\n");

  const lines = answer.replace(/\r\n/g, "\n").split("\n");
  const start = lines.findIndex((line) => /^(---|apiVersion:|kind:)/.test(line.trim()));

  return (start >= 0 ? lines.slice(start) : lines).join("\n").trim();
};

/**
 * How to ask a known AI tool one question without opening a session, by the tool Lens has selected.
 * `{prompt}` stands for the shell-quoted question.
 */
export const headlessCommandFor = (kind: string, name: string): string | undefined => {
  const tool = `${kind} ${name}`.toLowerCase();

  if (tool.includes("claude")) return "claude -p {prompt}";
  if (tool.includes("codex")) return "codex exec {prompt}";
  if (tool.includes("gemini")) return "gemini -p {prompt}";
  if (tool.includes("copilot")) return "copilot -p {prompt}";
  if (tool.includes("cursor")) return "cursor-agent -p {prompt}";
  if (tool.includes("opencode")) return "opencode run {prompt}";

  return undefined;
};

/**
 * The command line for a template, with the question quoted for the shell. Input is empty, since
 * some tools read a question from it when it is not a terminal and would wait; stderr is left out,
 * since they log progress there and Lens takes anything on it for a failure.
 */
export const commandLineFor = (template: string, quotedPrompt: string) =>
  `${template.includes("{prompt}") ? template.replace("{prompt}", () => quotedPrompt) : `${template} ${quotedPrompt}`} </dev/null 2>/dev/null`;
