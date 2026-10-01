import { Badge } from "@k8slens/badge";
import { Div, Span, Table, Td, TextArea, Th, Tr } from "@k8slens/element-components";
import { LayersIcon, NetworkIcon, SettingsIcon, SpinnerIcon } from "@k8slens/icon";
import { PlainButton, PrimaryButton, TextInput } from "@k8slens/input-components";
import { useInject } from "@k8slens/use-inject";
import { observer } from "mobx-react";
import type { LabDocument } from "../engines/lab/manifests";
import type { CheckStatus } from "../engines/policies/check";
import { Chips, CodeBlock, EffectBadge, Empty, EngineBadge, Muted, Notice, Page, PageHeader, plural, Section, Stat, ToneBadge } from "../ui/common";
import styles from "../ui/governance.module.scss";
import { labExamples } from "./examples";
import { describeRole, type LabWorkbench, labWorkbenchInjectable } from "./lab-workbench.injectable";

const checkTone: Record<CheckStatus, "success" | "critical" | "grey40" | "warning" | "primary"> = {
  pass: "success",
  fail: "critical",
  skip: "grey40",
  unknown: "warning",
  "not-a-check": "primary",
};

const checkLabel: Record<CheckStatus, string> = { pass: "complies", fail: "fails", skip: "not applied", unknown: "can't tell", "not-a-check": "changes it" };

const verdictText = {
  rejected: { tone: "critical", label: "REJECTED", text: "An enforcing rule fails: the API server would refuse it." },
  unsure: { tone: "warning", label: "UNSURE", text: "An enforcing rule applies that only its engine can evaluate." },
  warned: { tone: "warning", label: "WARNED", text: "Admitted, with a warning to the client." },
  reported: { tone: "notice", label: "ADMITTED, REPORTED", text: "Admitted, and recorded as a violation in the policy reports." },
  admitted: { tone: "success", label: "ADMITTED", text: "Every rule that applies is met." },
} as const;

const DocumentList = ({ documents, isDraft }: { documents: readonly LabDocument[]; isDraft: (document: LabDocument) => boolean }) =>
  documents.length === 0 ? null : (
    <Div $flex={{ direction: "horizontal", gap: "xs", wrap: true }}>
      {documents.map((document) => (
        <Badge
          key={document.id}
          small
          label={`${document.kind} ${document.namespace ? `${document.namespace}/` : ""}${document.name}`}
          $tooltip={`Line ${document.line}: ${isDraft(document) ? "a draft " : "tested as a "}${describeRole(document)}${document.problems.length > 0 ? `, ${document.problems.join(", ")}` : ""}`}
        />
      ))}
    </Div>
  );

const Editor = observer(
  ({ bench, which, title, hint }: { bench: LabWorkbench; which: "drafts" | "tests"; title: string; hint: string }) => {
    const { state } = bench;
    const value = which === "drafts" ? state.drafts.get() : state.tests.get();
    const set = which === "drafts" ? state.setDrafts : state.setTests;
    const append = which === "drafts" ? state.appendDrafts : state.appendTests;
    const documents = bench.lab.documents.get().filter((document) => document.source === which);
    const namespace = bench.network.namespaces.get().find((candidate) => candidate === "default") ?? bench.network.namespaces.get()[0] ?? "default";

    return (
      <Section
        title={title}
        actions={
          <>
            <Muted>Add:</Muted>
            <Chips
              options={labExamples.filter((example) => example.target === which).map((example) => ({ id: example.id, label: example.label }))}
              isSelected={() => false}
              onToggle={(id) => append(labExamples.find((example) => example.id === id)!.yaml(namespace))}
            />
            {value && (
              <PlainButton $tooltip="Empty this editor" onClick={() => set("")}>
                Clear
              </PlainButton>
            )}
          </>
        }
      >
        <Muted>{hint}</Muted>
        <TextArea
          $className={styles.yamlEditor}
          value={value}
          spellCheck={false}
          placeholder={"apiVersion: …\nkind: …\n---\napiVersion: …"}
          onChange={(event) => set(event.target.value)}
        />
        <DocumentList documents={documents} isDraft={(document) => which === "drafts" && document.role !== "workload"} />
      </Section>
    );
  },
);

const Generator = observer(({ bench }: { bench: LabWorkbench }) => {
  const { state } = bench;
  const tool = bench.tool.get();
  const run = state.aiRun.get();
  const request = state.aiRequest.get();
  const running = run.status === "running";

  return (
    <Section
      title="Write with AI"
      actions={
        <PlainButton Icon={SettingsIcon} $tooltip="The command the lab runs" onClick={() => state.setShowAiSettings(!state.showAiSettings.get())}>
          Command
        </PlainButton>
      }
    >
      <TextArea
        $className={styles.requestEditor}
        value={request}
        placeholder="Describe the policy: “only the frontend may reach the api pods on 8080”, “block images from outside ghcr.io/acme”, “every Deployment needs a team label”…"
        onChange={(event) => state.setAiRequest(event.target.value)}
      />
      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
        <PrimaryButton
          $disabled={!tool?.command || running || !request.trim()}
          $tooltip={tool?.command ? `Runs ${tool.command.split(" ")[0]} on this machine and puts its YAML below for you to review` : "No AI tool the lab can ask: see below"}
          onClick={() => void bench.generate()}
        >
          {tool ? `Generate with ${tool.name}` : "Generate"}
        </PrimaryButton>
        <PlainButton $tooltip="Opens Lens's Ask AI, briefed on the cluster and the lab; paste what it writes into the drafts" onClick={() => void bench.askAi()}>
          Ask AI instead
        </PlainButton>
        {running && (
          <Div $flex={{ direction: "horizontal", gap: "xs", verticalAlign: "center" }}>
            <SpinnerIcon $size="s" />
            <Muted>Asking {run.tool}: this can take a minute.</Muted>
          </Div>
        )}
      </Div>
      {!tool && <Muted>Select an AI tool in Lens's top bar to generate here, or set a command. Ask AI works either way.</Muted>}
      {tool && !tool.command && (
        <Muted>The lab does not know how to ask {tool.name} a single question from the command line: set its command, or use Ask AI.</Muted>
      )}
      {state.showAiSettings.get() && (
        <Div $flex={{ direction: "vertical", gap: "xxs" }}>
          <TextInput
            value={state.aiCommand.get()}
            placeholder={tool?.command && !tool.custom ? tool.command : "claude -p {prompt}"}
            spellCheck={false}
            onChange={(event) => state.setAiCommand(event.target.value)}
          />
          <Span $font={{ size: "xs" }} $color="textMuted">
            {"{prompt}"} becomes the request, shell-quoted. It runs on this machine and sends the request, the lab's manifests, and the names and labels of this cluster's
            namespaces, workloads and policies. Leave it empty to follow the tool selected in Lens.
          </Span>
        </Div>
      )}
      {run.status === "failed" && (
        <Notice tone="critical">
          <Div $flex={{ direction: "vertical", gap: "xxs" }}>
            <Span $font={{ bold: true }}>{run.tool} did not answer.</Span>
            <Span $font={{ size: "s" }}>{run.error}</Span>
            <Span $font={{ size: "s" }}>Run the command in a terminal to see why, or use Ask AI.</Span>
          </Div>
        </Notice>
      )}
      {run.status === "done" && (
        <Div $flex={{ direction: "vertical", gap: "s" }}>
          <Span $font={{ bold: true }}>{run.tool} wrote:</Span>
          {run.problems.map((problem) => (
            <Notice key={problem} tone="warning">
              {problem}
            </Notice>
          ))}
          <CodeBlock code={run.yaml} />
          <Div $flex={{ direction: "horizontal", gap: "s" }}>
            <PrimaryButton onClick={() => bench.acceptGenerated("add")}>Add to drafts</PrimaryButton>
            <PlainButton onClick={() => bench.acceptGenerated("replace")}>Replace drafts</PlainButton>
            <PlainButton onClick={bench.discardGenerated}>Discard</PlainButton>
          </Div>
        </Div>
      )}
    </Section>
  );
});

const AdmissionResults = observer(({ bench }: { bench: LabWorkbench }) => {
  const results = bench.admission.get();

  if (results.length === 0) return null;

  return (
    <Section title="Admission: what the API server would do with each test manifest">
      {results.map(({ document, checked, verdict, namespaceKnown }) => {
        const shown = verdictText[verdict];

        return (
          <Div key={document.id} $flex={{ direction: "vertical", gap: "xs" }} $padding={{ vertical: "xs" }}>
            <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
              <ToneBadge tone={shown.tone} label={shown.label} small={false} />
              <Span $font={{ bold: true }}>
                {document.kind} {document.namespace ? `${document.namespace}/` : ""}
                {document.name}
              </Span>
              <Muted>{shown.text}</Muted>
            </Div>
            {!namespaceKnown && <Muted>Namespace {document.namespace} does not exist yet: rules that select namespaces by label see none.</Muted>}
            {checked.length === 0 ? (
              <Muted>No admission rule applies to it.</Muted>
            ) : (
              <Table $className={styles.table}>
                <thead>
                  <Tr>
                    <Th>Effect</Th>
                    <Th>Policy and rule</Th>
                    <Th>Result</Th>
                    <Th>Why</Th>
                  </Tr>
                </thead>
                <tbody>
                  {checked.map((entry) => (
                    <Tr key={entry.rule.id}>
                      <Td>
                        <EffectBadge effect={entry.effect} />
                      </Td>
                      <Td>
                        <Div $flex={{ direction: "horizontal", gap: "xs", verticalAlign: "center", wrap: true }}>
                          <EngineBadge engine={entry.policy.ref.engine} />
                          {bench.policies.isDraftPolicy(entry.policy.ref) && <ToneBadge tone="primary" label="draft" />}
                          <Span>{entry.policy.title}</Span>
                          <Muted>· {entry.rule.name}</Muted>
                        </Div>
                      </Td>
                      <Td>
                        <ToneBadge tone={checkTone[entry.check.status]} label={checkLabel[entry.check.status]} />
                      </Td>
                      <Td>
                        <Span $font={{ size: "s" }}>{entry.check.detail}</Span>
                        {entry.caveats.length > 0 && (
                          <Span $font={{ size: "xs", italic: true }} $color="warning">
                            {" "}
                            Also: {entry.caveats.join("; ")}
                          </Span>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Div>
        );
      })}
    </Section>
  );
});

const NetworkResults = observer(({ bench }: { bench: LabWorkbench }) => {
  const reach = bench.reach.get();

  if (reach.length === 0) return null;

  return (
    <Section title="Network: how each test workload would be reachable">
      {reach.map((entry) => (
        <Div key={entry.document.id} $flex={{ direction: "vertical", gap: "xxs" }} $padding={{ vertical: "xs" }}>
          <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
            <Span $font={{ bold: true }}>
              {entry.document.kind} {entry.document.namespace}/{entry.document.name}
            </Span>
            {entry.pod && Object.keys(entry.pod.labels).length > 0 && (
              <Muted>{Object.entries(entry.pod.labels).map(([key, value]) => `${key}=${value}`).join(", ")}</Muted>
            )}
            <PlainButton Icon={NetworkIcon} onClick={() => void bench.simulateTo(entry.document)}>
              Who reaches it
            </PlainButton>
            <PlainButton onClick={() => void bench.simulateFrom(entry.document)}>What it reaches</PlainButton>
          </Div>
          {!entry.pod ? (
            <Muted>It has no pod template to place.</Muted>
          ) : (
            <>
              <Span $font={{ size: "s" }}>
                Ingress:{" "}
                {entry.ingressPolicies.length === 0 ? (
                  <Span $color="warning">no policy selects it, so it accepts traffic from anywhere</Span>
                ) : (
                  `isolated by ${entry.ingressPolicies.join(", ")}`
                )}
              </Span>
              <Span $font={{ size: "s" }}>
                Egress:{" "}
                {entry.egressPolicies.length === 0 ? <Span $color="warning">no policy selects it, so it may send anywhere</Span> : `isolated by ${entry.egressPolicies.join(", ")}`}
              </Span>
              {entry.inbound && (
                <Span $font={{ size: "s" }}>
                  {entry.inbound.allowed} of {plural(entry.inbound.of, "workload")} of the cluster may open {entry.inbound.protocol} {entry.inbound.port}
                  {entry.inbound.examples.length > 0 ? `: ${entry.inbound.examples.join(", ")}${entry.inbound.allowed > entry.inbound.examples.length ? ", …" : ""}` : "."}
                </Span>
              )}
              <Span $font={{ size: "s" }}>
                Outside the cluster on TCP 443: {entry.toOutside ? "allowed" : <Span $color="critical">blocked</Span>}
                {entry.toDns !== undefined && (
                  <>
                    {" · "}DNS: {entry.toDns ? "allowed" : <Span $color="critical">blocked, so names will not resolve</Span>}
                  </>
                )}
              </Span>
            </>
          )}
        </Div>
      ))}
      <Muted>Test workloads have no IP yet, so rules that admit addresses (ipBlock, CIDR) do not count them.</Muted>
    </Section>
  );
});

const DraftImpact = observer(({ bench }: { bench: LabWorkbench }) => {
  const network = bench.networkDrafts.get();
  const admission = bench.admissionImpact.get();

  if (network.length === 0 && admission.length === 0) return null;

  return (
    <Section title="What the drafts do to the cluster as it runs now">
      {network.map(({ key, policy, selected }) => (
        <Div key={key} $flex={{ direction: "vertical", gap: "zero" }}>
          <Span>
            <Badge small label={policy.direction} /> {policy.ref.kind} {policy.ref.namespace ? `${policy.ref.namespace}/` : ""}
            {policy.ref.name}: selects {plural(selected.length, "pod")}
            {selected.some((pod) => pod.lab) ? ` (${selected.filter((pod) => pod.lab).length} of them test workloads)` : ""}
            {policy.isolates && selected.length > 0 ? `, which then ${policy.direction === "ingress" ? "accept" : "send"} only what a policy allows` : ""}
          </Span>
          {selected.length > 0 && (
            <Span $font={{ size: "xs" }} $color="textMuted">
              {selected.slice(0, 10).map((pod) => `${pod.namespace}/${pod.name}${pod.lab ? " (test)" : ""}`).join(", ")}
              {selected.length > 10 ? `, and ${selected.length - 10} more` : ""}
            </Span>
          )}
        </Div>
      ))}
      {admission.map((impact) => (
        <Div key={`${impact.policy}/${impact.rule}`} $flex={{ direction: "vertical", gap: "zero" }}>
          <Span>
            {impact.policy} · {impact.rule}:{" "}
            {impact.tried === 0
              ? "applies to none of the running pods"
              : impact.failing.length === 0
                ? `all ${plural(impact.tried, "running pod")} it applies to comply`
                : `${impact.failing.length} of ${plural(impact.tried, "running pod")} it applies to would fail`}
            {impact.unknown > 0 ? ` (${impact.unknown} it cannot tell)` : ""}
          </Span>
          {impact.failing.slice(0, 5).map((failure) => (
            <Span key={failure.pod} $font={{ size: "xs" }} $color="textMuted">
              {failure.pod}: {failure.detail}
            </Span>
          ))}
          {impact.failing.length > 5 && <Muted>and {impact.failing.length - 5} more</Muted>}
        </Div>
      ))}
    </Section>
  );
});

export const LabView = observer(({ clusterId }: { clusterId: string }) => {
  const bench = useInject(labWorkbenchInjectable)(clusterId);
  const counts = bench.counts.get();
  const errors = bench.lab.parsed.get().errors;

  return (
    <Page>
      <PageHeader Icon={LayersIcon} title="Policy lab" subtitle="Draft policies and test manifests, checked against this cluster before anything is applied. Nothing here is sent to the cluster.">
        <Stat label="draft policies" value={counts.drafts} />
        <Stat label="test manifests" value={counts.tests} />
      </PageHeader>
      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
        <Chips
          options={[{ id: "apply", label: "Use the drafts in the other views", tooltip: "Admission policies and Network reachability simulate with the drafts laid over the cluster" }]}
          isSelected={() => bench.state.applyDrafts.get()}
          onToggle={() => bench.state.setApplyDrafts(!bench.state.applyDrafts.get())}
        />
        <Muted>A draft with the same kind, namespace and name as a policy of the cluster stands in for it. The lab is saved on this machine.</Muted>
      </Div>
      <Generator bench={bench} />
      <Div $className={styles.labEditors}>
        <Editor
          bench={bench}
          which="drafts"
          title="Draft policies"
          hint="NetworkPolicy, CiliumNetworkPolicy, Calico, Kyverno ClusterPolicy or Policy, Gatekeeper constraints. Separate documents with ---."
        />
        <Editor
          bench={bench}
          which="tests"
          title="Test manifests"
          hint="Pods, Deployments and other workloads, Services, Namespaces, or any resource to try against admission."
        />
      </Div>
      {errors.map((error) => (
        <Notice key={`${error.source}:${error.line}:${error.message}`} tone="warning">
          {error.source === "drafts" ? "Draft policies" : "Test manifests"}, line {error.line}: {error.message}
        </Notice>
      ))}
      {counts.drafts + counts.tests === 0 ? (
        <Empty>Write or generate a policy, add a test manifest, and the lab shows what admission and the network would do with them.</Empty>
      ) : (
        <>
          <AdmissionResults bench={bench} />
          <NetworkResults bench={bench} />
          <DraftImpact bench={bench} />
        </>
      )}
    </Page>
  );
});
