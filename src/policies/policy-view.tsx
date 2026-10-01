import { Badge } from "@k8slens/badge";
import { ClickableDiv, Div, Span, Table, Td, Th, Tr } from "@k8slens/element-components";
import { CheckCircleIcon, ExpandMoreIcon, KeyboardArrowRightIcon, PolicyIcon } from "@k8slens/icon";
import { TextInput } from "@k8slens/input-components";
import { LightWeightTabs } from "@k8slens/tabs-components";
import { useInject } from "@k8slens/use-inject";
import { observer } from "mobx-react";
import { type NormalizedRule, type PolicyEffect, type PolicyEngine, policyRefKey, type Requirement } from "../engines/policies/model";
import type { ApplicableRule } from "../engines/policies/simulate";
import {
  Chips,
  CodeBlock,
  EffectBadge,
  Empty,
  EngineBadge,
  Field,
  LoadStatus,
  Muted,
  Notice,
  Page,
  PageHeader,
  Picker,
  plural,
  RichText,
  Section,
  Stat,
  ToneBadge,
} from "../ui/common";
import styles from "../ui/governance.module.scss";
import { LabBanner } from "../lab/lab-banner";
import { type PolicyEntry, type PolicyModel, policyModelInjectable } from "./policy-model.injectable";

const engineOptions: readonly { id: PolicyEngine; label: string }[] = [
  { id: "kyverno", label: "Kyverno" },
  { id: "kyverno-cel", label: "Kyverno CEL" },
  { id: "gatekeeper", label: "Gatekeeper" },
];

const effectOptions: readonly { id: PolicyEffect; label: string }[] = [
  { id: "enforce", label: "Blocks" },
  { id: "audit", label: "Audits" },
  { id: "warn", label: "Warns" },
  { id: "mutate", label: "Mutates" },
  { id: "generate", label: "Generates" },
];

const Requirements = ({ requirements }: { requirements: readonly Requirement[] }) => (
  <Div $flex={{ direction: "vertical", gap: "xxs" }}>
    {requirements.map((requirement, index) => (
      <Div key={index} $flex={{ direction: "vertical", gap: "xxs" }} $padding={{ left: requirement.text.startsWith("  ") ? "l" : "zero" }}>
        <Span $font={{ size: "s" }}>
          <RichText text={requirement.text.trimStart()} />
        </Span>
        {requirement.code && <CodeBlock code={requirement.code} />}
      </Div>
    ))}
  </Div>
);

const RuleDetails = ({ rule }: { rule: NormalizedRule }) => (
  <Div $flex={{ direction: "vertical", gap: "xs" }} $padding="s" $border={{ color: "borderPrimary", width: "xxs", radius: "m" }}>
    <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
      <Span $font={{ bold: true }}>{rule.name}</Span>
      <Badge small label={rule.type} $tooltip="Rule type" />
      <EffectBadge effect={rule.effect} />
    </Div>
    <Div $flex={{ direction: "vertical", gap: "zero" }}>
      {rule.scope.map((line, index) => (
        <Span key={index} $font={{ size: "s" }} $color="textMuted">
          {line}
        </Span>
      ))}
    </Div>
    {rule.conditions.map((condition, index) => (
      <Span key={index} $font={{ size: "s", italic: true }}>
        {condition}
      </Span>
    ))}
    <Requirements requirements={rule.requirements} />
    {rule.message && (
      <Span $font={{ size: "s" }}>
        <Muted>Message on violation:</Muted> {rule.message}
      </Span>
    )}
  </Div>
);

const PolicyCard = observer(({ model, entry }: { model: PolicyModel; entry: PolicyEntry }) => {
  const { policy } = entry;
  const expanded = model.state.expanded.has(entry.key);
  const ownRules = policy.rules.filter((rule) => !rule.autogen);
  const effects = [...new Set(ownRules.map((rule) => rule.effect))];
  const failing = entry.results.fail + (policy.ref.engine === "gatekeeper" && entry.results.fail === 0 ? (policy.reportedViolations ?? 0) : 0);

  return (
    <Div $border={{ color: "borderPrimary", width: "xxs", radius: "m" }} $backgroundColor="backgroundPrimary">
      <ClickableDiv
        $padding={{ horizontal: "m", vertical: "s" }}
        $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}
        $onClick={() => model.state.toggleExpanded(entry.key)}
      >
        {expanded ? <ExpandMoreIcon $size="s" /> : <KeyboardArrowRightIcon $size="s" />}
        <EngineBadge engine={policy.ref.engine} />
        {model.isDraftPolicy(policy.ref) && <ToneBadge tone="primary" label="draft" tooltip="From the policy lab: not in the cluster" />}
        <Div $flex={{ direction: "vertical", gap: "zero" }} $flexChild="shrinkable">
          <Span $font={{ bold: true }}>{policy.title}</Span>
          <Span $font={{ size: "xs" }} $color="textMuted">
            {policy.ref.kind} {policy.ref.namespace ? `${policy.ref.namespace}/` : ""}
            {policy.ref.name} · {plural(ownRules.length, "rule")}
            {policy.category ? ` · ${policy.category}` : ""}
          </Span>
        </Div>
        {effects.map((effect) => (
          <EffectBadge key={effect} effect={effect} />
        ))}
        {policy.ready && !policy.ready.ok && <ToneBadge tone="critical" label="not ready" tooltip={policy.ready.message} />}
        {failing > 0 ? (
          <ToneBadge tone="critical" label={plural(failing, "violation")} tooltip="Failing results in policy reports, or the constraint's last audit" />
        ) : entry.results.pass > 0 ? (
          <Span $color="success" $tooltip={`${entry.results.pass} passing results`}>
            <CheckCircleIcon $size="s" />
          </Span>
        ) : null}
      </ClickableDiv>
      {expanded && (
        <Div $flex={{ direction: "vertical", gap: "s" }} $padding={{ horizontal: "m", bottom: "m" }}>
          {policy.description && <Span>{policy.description}</Span>}
          {policy.notes.map((note) => (
            <Notice key={note}>{note}</Notice>
          ))}
          {ownRules.map((rule) => (
            <RuleDetails key={rule.id} rule={rule} />
          ))}
          {entry.findings.length > 0 && (
            <Div $flex={{ direction: "vertical", gap: "xxs" }}>
              <Span $font={{ bold: true }}>Resources that do not comply</Span>
              {entry.findings.slice(0, 15).map((finding, index) => (
                <Span key={index} $font={{ size: "s" }}>
                  <ToneBadge tone={finding.result === "warn" ? "warning" : "critical"} label={finding.result} /> {finding.resource.kind}{" "}
                  {finding.resource.namespace ? `${finding.resource.namespace}/` : ""}
                  {finding.resource.name}
                  {finding.rule ? <Muted> · {finding.rule}</Muted> : null}
                  {finding.message ? <Muted> — {finding.message}</Muted> : null}
                </Span>
              ))}
              {entry.findings.length > 15 && <Muted>and {entry.findings.length - 15} more, under Violations</Muted>}
            </Div>
          )}
        </Div>
      )}
    </Div>
  );
});

const EngineStatus = observer(({ model }: { model: PolicyModel }) => {
  const installed = model.installed.get();

  if (!installed.settled) return null;

  const engines = [
    { label: "Kyverno", on: installed.kyverno },
    { label: "Kyverno CEL policies", on: installed.kyvernoCel },
    { label: "OPA Gatekeeper", on: installed.gatekeeper },
    { label: "Policy reports", on: installed.reports },
  ];

  return (
    <Div $flex={{ direction: "horizontal", gap: "s", wrap: true, verticalAlign: "center" }}>
      {engines.map((engine) => (
        <ToneBadge key={engine.label} tone={engine.on ? "success" : "grey60"} label={`${engine.label}: ${engine.on ? "installed" : "not installed"}`} />
      ))}
    </Div>
  );
});

const PolicyList = observer(({ model }: { model: PolicyModel }) => {
  const entries = model.visibleEntries.get();
  const installed = model.installed.get();

  return (
    <Div $flex={{ direction: "vertical", gap: "s" }}>
      <Div $flex={{ direction: "horizontal", gap: "m", wrap: true, verticalAlign: "center" }}>
        <Div $className={styles.searchBox}>
          <TextInput type="search" placeholder="Filter policies" value={model.state.search.get()} onChange={(event) => model.state.setSearch(event.target.value)} />
        </Div>
        <Chips options={engineOptions} isSelected={(id) => model.state.engines.has(id)} onToggle={model.state.toggleEngine} />
        <Chips options={effectOptions} isSelected={(id) => model.state.effects.has(id)} onToggle={model.state.toggleEffect} />
      </Div>
      {entries.map((entry) => (
        <PolicyCard key={entry.key} model={model} entry={entry} />
      ))}
      {entries.length === 0 &&
        (installed.settled && !installed.kyverno && !installed.kyvernoCel && !installed.gatekeeper ? (
          <Empty>Neither Kyverno nor OPA Gatekeeper is installed in this cluster.</Empty>
        ) : (
          <Empty>No policy matches.</Empty>
        ))}
    </Div>
  );
});

const operationOptions = [
  { id: "CREATE" as const, label: "Create" },
  { id: "UPDATE" as const, label: "Update" },
  { id: "DELETE" as const, label: "Delete" },
];

const effectHeadings: Record<PolicyEffect, string> = {
  enforce: "Rejected unless it complies",
  warn: "Allowed, with a warning unless it complies",
  audit: "Allowed, and reported unless it complies",
  mutate: "Changed on the way in",
  generate: "Makes other resources appear",
};

const ApplicableCard = observer(({ model, entry }: { model: PolicyModel; entry: ApplicableRule }) => (
  <Div $flex={{ direction: "vertical", gap: "xs" }} $padding="s" $border={{ color: "borderPrimary", width: "xxs", radius: "m" }}>
    <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
      <EngineBadge engine={entry.policy.ref.engine} />
      {model.isDraftPolicy(entry.policy.ref) && <ToneBadge tone="primary" label="draft" tooltip="From the policy lab: not in the cluster" />}
      <ClickableDiv $color="link" $tooltip="Show the whole policy" $onClick={() => model.state.showPolicy(policyRefKey(entry.policy.ref), entry.policy.ref.name)}>
        <Span $font={{ bold: true }}>{entry.policy.title}</Span>
      </ClickableDiv>
      <Muted>· {entry.rule.name}</Muted>
      {entry.effect !== entry.rule.effect && <Badge small label="namespace override" $tooltip={`This namespace overrides the rule's default (${entry.rule.effect})`} />}
    </Div>
    <Requirements requirements={entry.rule.requirements} />
    {entry.rule.message && (
      <Span $font={{ size: "s" }}>
        <Muted>Says:</Muted> {entry.rule.message}
      </Span>
    )}
    <Span $font={{ size: "xs" }} $color="textMuted">
      Applies because: {entry.reasons.join(", ") || "it matches every resource"}
    </Span>
    {entry.caveats.map((caveat) => (
      <Span key={caveat} $font={{ size: "xs", italic: true }} $color="warning">
        Only if: {caveat}
      </Span>
    ))}
    {entry.possibleExemption && (
      <Span $font={{ size: "xs", italic: true }}>
        May be exempted by PolicyException {entry.possibleExemption.exception.namespace ? `${entry.possibleExemption.exception.namespace}/` : ""}
        {entry.possibleExemption.exception.name}
        {entry.possibleExemption.condition ? `, when ${entry.possibleExemption.condition}` : ""}
      </Span>
    )}
  </Div>
));

const Simulator = observer(({ model }: { model: PolicyModel }) => {
  const form = model.state.simulation;
  const result = model.simulation.get();
  const kind = model.simulationKinds.find((candidate) => candidate.kind.toLowerCase() === form.kind.trim().toLowerCase());
  const counts = (Object.keys(effectHeadings) as PolicyEffect[]).map((effect) => ({ effect, count: result.byEffect[effect].length })).filter((entry) => entry.count > 0);

  return (
    <Div $flex={{ direction: "vertical", gap: "m" }}>
      <Section title="What applies to…">
        <Div $flex={{ direction: "horizontal", gap: "s", wrap: true, verticalAlign: "bottom" }}>
          <Field label="Kind">
            <Picker value={form.kind} onChange={(value) => model.state.setSimulation({ kind: value })} options={model.simulationKinds.map((entry) => ({ value: entry.kind, label: `${entry.group || "core"}${entry.namespaced ? "" : " · cluster-scoped"}` }))} />
          </Field>
          {(kind?.namespaced ?? true) && (
            <Field label="Namespace">
              <Picker value={form.namespace} onChange={(value) => model.state.setSimulation({ namespace: value })} options={model.namespaces.get().map((value) => ({ value }))} />
            </Field>
          )}
          <Field label="Name (optional)">
            <TextInput value={form.name} onChange={(event) => model.state.setSimulation({ name: event.target.value })} />
          </Field>
          <Field label="Labels" grow>
            <TextInput placeholder="app=web, team=checkout" value={form.labels} onChange={(event) => model.state.setSimulation({ labels: event.target.value })} />
          </Field>
          <Field label="Operation">
            <Chips options={operationOptions} isSelected={(id) => form.operation === id} onToggle={(operation) => model.state.setSimulation({ operation })} />
          </Field>
        </Div>
        {!result.namespaceKnown && <Muted>Namespace {result.target.namespace} does not exist yet: its labels are taken to be none.</Muted>}
        {!kind && form.kind.trim() && <Muted>{form.kind} is not a kind this view knows: matched by its name, in the core group, as {result.target.resource}.</Muted>}
      </Section>

      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
        <Span $font={{ size: "l", bold: true }}>
          {result.applicable.length === 0 ? "No admission rule applies." : `${plural(result.applicable.length, "rule")} apply:`}
        </Span>
        {counts.map(({ effect, count }) => (
          <Span key={effect}>
            <EffectBadge effect={effect} /> {count}
          </Span>
        ))}
      </Div>

      {(Object.keys(effectHeadings) as PolicyEffect[]).map((effect) =>
        result.byEffect[effect].length === 0 ? null : (
          <Section key={effect} title={effectHeadings[effect]}>
            {result.byEffect[effect].map((entry) => (
              <ApplicableCard key={entry.rule.id} model={model} entry={entry} />
            ))}
          </Section>
        ),
      )}

      <Section
        title={`Rules that do not apply (${result.skipped.length})`}
        actions={
          <Chips
            options={[{ id: "show", label: model.state.showSkipped.get() ? "Hide" : "Show why" }]}
            isSelected={() => model.state.showSkipped.get()}
            onToggle={() => model.state.setShowSkipped(!model.state.showSkipped.get())}
          />
        }
      >
        {model.state.showSkipped.get() &&
          result.skipped.map((entry) => (
            <Span key={entry.rule.id} $font={{ size: "s" }}>
              <EngineBadge engine={entry.policy.ref.engine} /> {entry.policy.title} · {entry.rule.name}
              <Muted> — {entry.reason}</Muted>
            </Span>
          ))}
      </Section>
    </Div>
  );
});

const resultOptions = [
  { id: "fail" as const, label: "Fail" },
  { id: "warn" as const, label: "Warn" },
  { id: "error" as const, label: "Error" },
];

const Violations = observer(({ model }: { model: PolicyModel }) => {
  const violations = model.violations.get();

  return (
    <Div $flex={{ direction: "vertical", gap: "s" }}>
      <Div $flex={{ direction: "horizontal", gap: "m", wrap: true, verticalAlign: "center" }}>
        <Div $className={styles.searchBox}>
          <TextInput
            type="search"
            placeholder="Filter by resource, namespace, policy or message"
            value={model.state.violationSearch.get()}
            onChange={(event) => model.state.setViolationSearch(event.target.value)}
          />
        </Div>
        <Chips options={resultOptions} isSelected={(id) => model.state.violationResults.has(id)} onToggle={model.state.toggleViolationResult} />
      </Div>
      {violations.length === 0 ? (
        <Empty>No resource is reported out of compliance.</Empty>
      ) : (
        <Table $className={styles.table}>
          <thead>
            <Tr>
              <Th>Result</Th>
              <Th>Resource</Th>
              <Th>Policy</Th>
              <Th>Message</Th>
            </Tr>
          </thead>
          <tbody>
            {violations.slice(0, 500).map((violation, index) => {
              const key = model.policyKeyOf(violation.engine, violation.policy, violation.policyNamespace);

              return (
                <Tr key={index}>
                  <Td>
                    <ToneBadge tone={violation.result === "warn" ? "warning" : "critical"} label={violation.result} />
                  </Td>
                  <Td>
                    {violation.resource.kind} {violation.resource.namespace ? `${violation.resource.namespace}/` : ""}
                    {violation.resource.name}
                  </Td>
                  <Td>
                    {key ? (
                      <ClickableDiv $color="link" $onClick={() => model.state.showPolicy(key, violation.policy)}>
                        {violation.policy}
                      </ClickableDiv>
                    ) : (
                      violation.policy
                    )}
                    {violation.rule && <Muted> · {violation.rule}</Muted>}
                  </Td>
                  <Td>
                    <Span $font={{ size: "s" }}>{violation.message}</Span>
                  </Td>
                </Tr>
              );
            })}
          </tbody>
        </Table>
      )}
      {violations.length > 500 && <Muted>Showing 500 of {violations.length}; filter to narrow them down.</Muted>}
    </Div>
  );
});

export const PolicyView = observer(({ clusterId }: { clusterId: string }) => {
  const model = useInject(policyModelInjectable)(clusterId);
  const totals = model.totals.get();
  const constraints = model.constraints.get();

  return (
    <Page>
      <PageHeader Icon={PolicyIcon} title="Admission policies" subtitle="What Kyverno and OPA Gatekeeper require of resources, where, and what they do when a resource does not comply.">
        <Stat label="policies" value={totals.policies} />
        <Stat label="blocking" value={totals.enforcing} />
        <Stat label="failing results" value={totals.failing} tone={totals.failing > 0 ? "critical" : undefined} />
      </PageHeader>
      <EngineStatus model={model} />
      <LabBanner clusterId={model.clusterId} />
      <LoadStatus
        snapshot={{ loading: model.snapshot.get().loading || constraints.loading, failures: [...model.snapshot.get().failures, ...constraints.failures] }}
        extraFailures={model.readFailures.get()}
      />
      <LightWeightTabs
        tabs={[
          { id: "policies", label: "Policies" },
          { id: "simulate", label: "What applies?" },
          { id: "violations", label: "Violations", badge: totals.failing + totals.warning > 0 ? <Badge small label={String(totals.failing + totals.warning)} /> : undefined },
        ]}
        selected={model.state.subView.get()}
        onSelect={(view) => view && model.state.setSubView(view)}
      />
      {model.state.subView.get() === "policies" && <PolicyList model={model} />}
      {model.state.subView.get() === "simulate" && <Simulator model={model} />}
      {model.state.subView.get() === "violations" && <Violations model={model} />}
    </Page>
  );
});
