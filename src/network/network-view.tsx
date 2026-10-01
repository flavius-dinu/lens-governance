import { Badge } from "@k8slens/badge";
import { ClickableDiv, Div, Span, Table, Td, Th, Tr } from "@k8slens/element-components";
import { CompareArrowsIcon, NetworkIcon } from "@k8slens/icon";
import { PlainButton, TextInput } from "@k8slens/input-components";
import { LightWeightTabs } from "@k8slens/tabs-components";
import { useInject } from "@k8slens/use-inject";
import { observer } from "mobx-react";
import type { FlowVerdict, SideVerdict } from "../engines/net/evaluate";
import { endpointLabel, netEngineLabel, netPolicyRefKey, type Protocol } from "../engines/net/model";
import { Chips, Empty, Field, LoadStatus, Muted, Notice, Page, PageHeader, plural, Section, Stat, ToneBadge, VerdictBadge } from "../ui/common";
import styles from "../ui/governance.module.scss";
import { LabBanner } from "../lab/lab-banner";
import { SearchPicker } from "../ui/search-picker";
import { FlowDiagram, ServiceDiagram } from "./flow-diagram";
import { isSystemNamespace, matrixLimit, type NetworkModelView, networkModelInjectable } from "./network-model.injectable";

const protocolOptions: readonly { id: Protocol; label: string }[] = [
  { id: "TCP", label: "TCP" },
  { id: "UDP", label: "UDP" },
  { id: "SCTP", label: "SCTP" },
];

const ruleClass = (side: SideVerdict, policyKey: string, ruleIndex: number, matched: boolean) => {
  const decided = side.decidedBy && netPolicyRefKey(side.decidedBy.policy.ref) === policyKey && side.decidedBy.rule.index === ruleIndex;

  if (decided) return side.allowed ? styles.ruleDecided : styles.ruleDeniedDecided;

  return matched ? styles.ruleMatched : styles.ruleIdle;
};

const SideCard = ({ title, side, absent }: { title: string; side?: SideVerdict; absent: string }) => (
  <Section
    title={title}
    actions={side ? <VerdictBadge allowed={side.allowed} small /> : <Badge small label="not governed" />}
    $flexChild
  >
    {!side ? (
      <Muted>{absent}</Muted>
    ) : (
      <Div $flex={{ direction: "vertical", gap: "s" }}>
        <Span>{side.summary}</Span>
        {side.trace.map((entry) => {
          const key = netPolicyRefKey(entry.policy.ref);

          return (
            <Div key={`${key}/${entry.policy.direction}`} $flex={{ direction: "vertical", gap: "xxs" }}>
              <Div $flex={{ direction: "horizontal", gap: "xs", verticalAlign: "center", wrap: true }}>
                <Badge small label={netEngineLabel[entry.policy.ref.engine]} />
                <Span $font={{ bold: true }}>
                  {entry.policy.ref.kind} {entry.policy.ref.namespace ? `${entry.policy.ref.namespace}/` : ""}
                  {entry.policy.ref.name}
                </Span>
                {entry.policy.tier && <Muted>tier {entry.policy.tier}</Muted>}
                {entry.policy.order !== undefined && <Muted>order {entry.policy.order}</Muted>}
              </Div>
              <Span $font={{ size: "xs" }} $color="textMuted">
                Selects {entry.policy.selectorText}
              </Span>
              {entry.rules.length === 0 && (
                <Span $font={{ size: "s" }} $color="critical">
                  No {entry.policy.direction} rules: allows nothing
                </Span>
              )}
              {entry.rules.map(({ rule, matched }) => (
                <Div key={rule.index} $className={ruleClass(side, key, rule.index, matched)}>
                  <Span $font={{ size: "s" }}>
                    {rule.text}
                    {matched ? " ✓" : ""}
                  </Span>
                </Div>
              ))}
            </Div>
          );
        })}
        {side.caveats.map((caveat) => (
          <Span key={caveat} $font={{ size: "xs", italic: true }} $color="warning">
            Caveat: {caveat}
          </Span>
        ))}
      </Div>
    )}
  </Section>
);

const FlowDetails = ({ verdict }: { verdict: FlowVerdict }) => (
  <Div $flex={{ direction: "horizontal", gap: "m", verticalAlign: "top", wrap: true }}>
    <SideCard
      title={`Egress from ${endpointLabel(verdict.source)}`}
      side={verdict.egress}
      absent="The source is outside the cluster: no egress policy of the cluster applies to it."
    />
    <SideCard
      title={`Ingress to ${endpointLabel(verdict.destination)}`}
      side={verdict.ingress}
      absent="The destination is outside the cluster: no ingress policy of the cluster applies to it."
    />
  </Div>
);

const Headline = ({ allowed, text }: { allowed: boolean; text: string }) => (
  <Div $flex={{ direction: "horizontal", gap: "m", verticalAlign: "center" }}>
    <VerdictBadge allowed={allowed} />
    <Span $font={{ size: "l", bold: true }}>{text}</Span>
  </Div>
);

const flowSentence = (verdict: FlowVerdict) => {
  const where = `${endpointLabel(verdict.source)} → ${endpointLabel(verdict.destination)} on ${verdict.traffic.protocol} ${verdict.traffic.port}`;

  if (verdict.allowed) return `${where} is allowed.`;

  const blocked = [verdict.egress && !verdict.egress.allowed ? "egress of the source" : undefined, verdict.ingress && !verdict.ingress.allowed ? "ingress of the destination" : undefined]
    .filter(Boolean)
    .join(" and ");

  return `${where} is blocked by the ${blocked}.`;
};

const DnsLine = ({ dns }: { dns?: FlowVerdict }) =>
  dns ? (
    <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center" }}>
      <VerdictBadge allowed={dns.allowed} small />
      <Span $font={{ size: "s" }}>
        DNS: resolving the service by name needs UDP 53 to {endpointLabel(dns.destination)}, which is {dns.allowed ? "allowed" : "blocked"}
        {!dns.allowed ? `: ${dns.egress && !dns.egress.allowed ? dns.egress.summary : dns.ingress?.summary}` : "."}
      </Span>
    </Div>
  ) : null;

const Simulator = observer(({ model }: { model: NetworkModelView }) => {
  const { state } = model;
  const result = model.simulation.get();
  const destination = model.destination.get();
  const options = model.endpointOptions.get();
  const podOptions = options.filter((option) => option.value.startsWith("pod:"));

  return (
    <Div $flex={{ direction: "vertical", gap: "m" }}>
      <Section title="Can this reach that?">
        <Div $flex={{ direction: "horizontal", gap: "s", wrap: true, verticalAlign: "bottom" }}>
          <Field label="From: a pod, or an IP outside the cluster" grow>
            <SearchPicker value={state.source.get()} onChange={state.setSource} options={podOptions} placeholder="Search pods by name, namespace or workload, or type an IP" hint="or type an IP address" />
          </Field>
          <PlainButton Icon={CompareArrowsIcon} onClick={state.swap} $tooltip="Swap source and destination">
            Swap
          </PlainButton>
          <Field label="To: a pod, a service, or an IP" grow>
            <SearchPicker value={state.destination.get()} onChange={state.setDestination} options={options} placeholder="Search pods and services, or type an IP" hint="or type an IP address" />
          </Field>
          {destination.type === "service" ? (
            <Field label="Service port">
              <Chips
                options={destination.service.ports.map((port) => ({ id: String(port.port), label: `${port.name ? `${port.name} ` : ""}${port.port}/${port.protocol}` }))}
                isSelected={(id) => (state.servicePort.get() || String(destination.service.ports[0]?.port)) === id}
                onToggle={state.setServicePort}
              />
            </Field>
          ) : (
            <>
              <Field label="Port">
                <Div $className={styles.portInput}>
                  <TextInput value={state.port.get()} onChange={(event) => state.setPort(event.target.value)} $width="full" inputMode="numeric" />
                </Div>
              </Field>
              <Field label="Protocol">
                <Chips options={protocolOptions} isSelected={(id) => state.protocol.get() === id} onToggle={state.setProtocol} />
              </Field>
            </>
          )}
        </Div>
      </Section>

      {result.type === "incomplete" && <Muted>{result.message}</Muted>}

      {result.type === "flow" && (
        <Div $flex={{ direction: "vertical", gap: "m" }}>
          <Headline allowed={result.verdict.allowed} text={flowSentence(result.verdict)} />
          <FlowDiagram verdict={result.verdict} />
          {result.verdict.notes.map((note) => (
            <Notice key={note}>{note}</Notice>
          ))}
          <FlowDetails verdict={result.verdict} />
        </Div>
      )}

      {result.type === "service" && (
        <Div $flex={{ direction: "vertical", gap: "m" }}>
          <Headline
            allowed={result.verdict.anyAllowed}
            text={
              result.verdict.backends.length === 0
                ? `${result.verdict.service.name} has no backend to reach.`
                : result.verdict.allAllowed
                  ? `Every backend of ${result.verdict.service.name} is reachable on ${result.verdict.servicePort.port}.`
                  : result.verdict.anyAllowed
                    ? `Only some backends of ${result.verdict.service.name} are reachable: requests fail when balanced to the others.`
                    : `No backend of ${result.verdict.service.name} is reachable on ${result.verdict.servicePort.port}.`
            }
          />
          <ServiceDiagram source={result.source} verdict={result.verdict} />
          <DnsLine dns={result.dns} />
          {result.verdict.notes.map((note) => (
            <Notice key={note}>{note}</Notice>
          ))}
          {result.verdict.backends.map((backend) =>
            backend.verdict ? (
              <Div key={backend.pod.uid} $flex={{ direction: "vertical", gap: "s" }}>
                <Span $font={{ bold: true }}>
                  Backend {backend.pod.name} on {backend.verdict.traffic.protocol} {backend.targetPort}
                </Span>
                <FlowDetails verdict={backend.verdict} />
              </Div>
            ) : (
              <Notice key={backend.pod.uid} tone="warning">
                {backend.pod.name}: {backend.problem}
              </Notice>
            ),
          )}
        </Div>
      )}
    </Div>
  );
});

/** One cell of the matrix: coloured by its verdict, and a control that opens the flow in the simulator. */
const MatrixCell = ({ className, tooltip, glyph, onOpen }: { className: string; tooltip: string; glyph: string; onOpen?: () => void }) => (
  <Td $className={[styles.cell, className]}>
    {onOpen ? (
      <ClickableDiv $onClick={onOpen} $tooltip={tooltip}>
        {glyph}
      </ClickableDiv>
    ) : (
      <Span $tooltip={tooltip}>{glyph}</Span>
    )}
  </Td>
);

const glyphOf = (tried: number, allowed: number) => (tried === 0 ? "·" : allowed === tried ? "✓" : allowed === 0 ? "✕" : "½");

const cellClass = (tried: number, allowed: number) =>
  tried === 0 ? styles.cellEmpty : allowed === tried ? styles.cellAll : allowed === 0 ? styles.cellNone : styles.cellSome;

const Matrix = observer(({ model }: { model: NetworkModelView }) => {
  const { state } = model;
  const { groups, cells, truncated, fromOutside, toOutside, ports } = model.matrix.get();
  const chosen = new Set(model.matrixNamespaces.get());
  const namespaces = model.namespaces.get();
  const label = (group: (typeof groups)[number]) => `${group.namespace}/${group.name}`;
  const simulate = (source: string, destination: string, port?: number, protocol?: Protocol) => state.simulateBetween(source, destination, port, protocol);

  return (
    <Div $flex={{ direction: "vertical", gap: "m" }}>
      <Section title="Which workloads can reach which">
        <Field label="Namespaces">
          <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
            <PlainButton $tooltip="Every namespace, the system ones included" onClick={() => state.setMatrixNamespaces(namespaces)}>
              All namespaces
            </PlainButton>
            <PlainButton
              $tooltip="Every namespace except kube-system, the -system ones and other platform namespaces"
              onClick={() => state.setMatrixNamespaces(namespaces.filter((namespace) => !isSystemNamespace(namespace)))}
            >
              All but system
            </PlainButton>
            <PlainButton $tooltip="Back to the first few application namespaces" onClick={() => state.setMatrixNamespaces([])}>
              Reset
            </PlainButton>
            <Muted>
              {chosen.size} of {namespaces.length} shown
            </Muted>
          </Div>
          <Chips
            options={namespaces.map((namespace) => ({ id: namespace, label: namespace }))}
            isSelected={(namespace) => chosen.has(namespace)}
            // From what is shown, the default included, so picking one more adds to it.
            onToggle={(namespace) => state.setMatrixNamespaces(chosen.has(namespace) ? [...chosen].filter((entry) => entry !== namespace) : [...chosen, namespace])}
          />
        </Field>
        <Div $flex={{ direction: "horizontal", gap: "m", wrap: true, verticalAlign: "bottom" }}>
          <Field label="Ports">
            <Chips
              options={[
                { id: "declared" as const, label: "Each destination's container ports" },
                { id: "fixed" as const, label: "One port" },
              ]}
              isSelected={(id) => state.matrixPortMode.get() === id}
              onToggle={state.setMatrixPortMode}
            />
          </Field>
          {state.matrixPortMode.get() === "fixed" && (
            <>
              <Field label="Port">
                <Div $className={styles.portInput}>
                  <TextInput value={state.matrixPort.get()} onChange={(event) => state.setMatrixPort(event.target.value)} $width="full" inputMode="numeric" />
                </Div>
              </Field>
              <Field label="Protocol">
                <Chips options={protocolOptions} isSelected={(id) => state.matrixProtocol.get() === id} onToggle={state.setMatrixProtocol} />
              </Field>
            </>
          )}
        </Div>
        <Div $flex={{ direction: "horizontal", gap: "m", wrap: true, verticalAlign: "center" }}>
          <Span $font={{ size: "s" }}>
            <Span $className={[styles.cell, styles.cellAll]} $padding={{ horizontal: "xs" }}>
              ✓
            </Span>{" "}
            allowed
          </Span>
          <Span $font={{ size: "s" }}>
            <Span $className={[styles.cell, styles.cellSome]} $padding={{ horizontal: "xs" }}>
              ½
            </Span>{" "}
            some ports
          </Span>
          <Span $font={{ size: "s" }}>
            <Span $className={[styles.cell, styles.cellNone]} $padding={{ horizontal: "xs" }}>
              ✕
            </Span>{" "}
            denied
          </Span>
          <Span $font={{ size: "s" }}>
            <Span $className={[styles.cell, styles.cellEmpty]} $padding={{ horizontal: "xs" }}>
              ·
            </Span>{" "}
            no declared port
          </Span>
          <Muted>Rows send, columns receive. Click a cell to open it in the simulator.</Muted>
        </Div>
      </Section>
      {truncated > 0 && <Notice>Showing the first {matrixLimit} workloads; {plural(truncated, "more is", "more are")} left out. Pick fewer namespaces to see them.</Notice>}
      {groups.length === 0 ? (
        <Empty>No workloads in the chosen namespaces.</Empty>
      ) : (
        <Div $overflow="auto">
          <Table $className={styles.matrix}>
            <thead>
              <Tr>
                <Th />
                {groups.map((group) => (
                  <Th key={group.key} $className={styles.colHead} title={`${group.kind} ${label(group)}`}>
                    {label(group)}
                  </Th>
                ))}
                <Th $className={styles.colHead} title="An address outside the cluster, on 443 unless a port is chosen">
                  outside
                </Th>
              </Tr>
            </thead>
            <tbody>
              {groups.map((source, row) => (
                <Tr key={source.key}>
                  <Th $className={styles.rowHead} title={`${source.kind} ${label(source)}`}>
                    {label(source)}
                  </Th>
                  {groups.map((destination, column) => {
                    const cell = cells[row]![column]!;
                    const self = row === column;
                    const first = cell.ports.find((entry) => !entry.allowed) ?? cell.ports[0];

                    if (self) return <MatrixCell key={destination.key} className={styles.cellSelf} tooltip="The same workload" glyph="" />;

                    return (
                      <MatrixCell
                        key={destination.key}
                        className={cellClass(cell.tried, cell.allowed)}
                        glyph={glyphOf(cell.tried, cell.allowed)}
                        tooltip={`${label(source)} → ${label(destination)}: ${
                          cell.tried === 0
                            ? "the destination declares no ports"
                            : cell.ports.map((entry) => `${entry.traffic.protocol} ${entry.traffic.port} ${entry.allowed ? "allowed" : "denied"}`).join(", ")
                        }`}
                        onOpen={() =>
                          simulate(
                            `pod:${source.pods[0]!.namespace}/${source.pods[0]!.name}`,
                            `pod:${destination.pods[0]!.namespace}/${destination.pods[0]!.name}`,
                            first?.traffic.port,
                            first?.traffic.protocol,
                          )
                        }
                      />
                    );
                  })}
                  <MatrixCell
                    className={toOutside[row] ? styles.cellAll : styles.cellNone}
                    glyph={toOutside[row] ? "✓" : "✕"}
                    tooltip={`${label(source)} → outside: ${toOutside[row] ? "allowed" : "denied"}`}
                    onOpen={() =>
                      simulate(
                        `pod:${source.pods[0]!.namespace}/${source.pods[0]!.name}`,
                        model.outsideIp,
                        ports.type === "fixed" ? ports.traffic.port : 443,
                        ports.type === "fixed" ? ports.traffic.protocol : "TCP",
                      )
                    }
                  />
                </Tr>
              ))}
              <Tr>
                <Th $className={styles.rowHead} title="An address outside the cluster">
                  outside
                </Th>
                {groups.map((destination, column) => {
                  const cell = fromOutside[column]!;
                  const pod = destination.pods[0]!;

                  return (
                    <MatrixCell
                      key={destination.key}
                      className={cellClass(cell.tried, cell.allowed)}
                      glyph={glyphOf(cell.tried, cell.allowed)}
                      tooltip={`outside → ${label(destination)}: ${cell.tried === 0 ? "no declared ports" : `${cell.allowed} of ${cell.tried} ports allowed`}`}
                      onOpen={() =>
                        simulate(
                          model.outsideIp,
                          `pod:${pod.namespace}/${pod.name}`,
                          ports.type === "fixed" ? ports.traffic.port : pod.ports[0]?.port,
                          ports.type === "fixed" ? ports.traffic.protocol : pod.ports[0]?.protocol,
                        )
                      }
                    />
                  );
                })}
                <MatrixCell className={styles.cellSelf} tooltip="" glyph="" />
              </Tr>
            </tbody>
          </Table>
        </Div>
      )}
    </Div>
  );
});

const Ratio = ({ part, whole }: { part: number; whole: number }) => {
  const share = whole === 0 ? 0 : part / whole;

  return (
    <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center" }}>
      <Div $className={styles.bar}>
        <Div $className={[styles.barFill, { [styles.barFillWarn]: share < 1 }]} $style={{ width: `${Math.round(share * 100)}%` }} />
      </Div>
      <Span $font={{ size: "s" }}>
        {part}/{whole}
      </Span>
    </Div>
  );
};

const Coverage = observer(({ model }: { model: NetworkModelView }) => {
  const rows = model.coverage.get();

  return (
    <Section
      title="How isolated each namespace is"
      actions={
        <Chips
          options={[{ id: "system", label: "Hide system namespaces" }]}
          isSelected={() => model.state.coverageHideSystem.get()}
          onToggle={() => model.state.setCoverageHideSystem(!model.state.coverageHideSystem.get())}
        />
      }
    >
      <Muted>A pod no policy selects for a direction accepts (or sends) anything. Least isolated namespaces first.</Muted>
      <Table $className={styles.table}>
        <thead>
          <Tr>
            <Th>Namespace</Th>
            <Th>Pods with ingress isolated</Th>
            <Th>Pods with egress isolated</Th>
            <Th>Default deny</Th>
            <Th>Policies</Th>
          </Tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <Tr key={row.namespace}>
              <Td>
                {row.namespace}
                {isSystemNamespace(row.namespace) && <Muted> (system)</Muted>}
              </Td>
              <Td>
                <Ratio part={row.ingressIsolated} whole={row.pods} />
              </Td>
              <Td>
                <Ratio part={row.egressIsolated} whole={row.pods} />
              </Td>
              <Td>
                <Div $flex={{ direction: "horizontal", gap: "xs" }}>
                  {row.defaultDenyIngress && <ToneBadge tone="success" label="ingress" />}
                  {row.defaultDenyEgress && <ToneBadge tone="success" label="egress" />}
                  {!row.defaultDenyIngress && !row.defaultDenyEgress && <Muted>none</Muted>}
                </Div>
              </Td>
              <Td>{row.policies}</Td>
            </Tr>
          ))}
        </tbody>
      </Table>
    </Section>
  );
});

const PolicyList = observer(({ model }: { model: NetworkModelView }) => {
  const entries = model.policyList.get();

  return (
    <Div $flex={{ direction: "vertical", gap: "s" }}>
      <Div $className={styles.searchBox}>
        <TextInput type="search" placeholder="Filter policies" value={model.state.policySearch.get()} onChange={(event) => model.state.setPolicySearch(event.target.value)} />
      </Div>
      {entries.length === 0 && <Empty>No network policy.</Empty>}
      {entries.map(({ policy, selected }) => (
        <Section
          key={`${netPolicyRefKey(policy.ref)}/${policy.direction}`}
          title={
            <Div $flex={{ direction: "horizontal", gap: "xs", verticalAlign: "center", wrap: true }}>
              <Badge small label={netEngineLabel[policy.ref.engine]} />
              <Badge small label={policy.direction} />
              {model.isDraftPolicy(policy.ref) && <ToneBadge tone="primary" label="draft" tooltip="From the policy lab: not in the cluster" />}
              <Span>
                {policy.ref.kind} {policy.ref.namespace ? `${policy.ref.namespace}/` : ""}
                {policy.ref.name}
              </Span>
            </Div>
          }
          actions={<Muted>{plural(selected.length, "pod")} selected</Muted>}
        >
          <Span $font={{ size: "s" }} $color="textMuted">
            Selects {policy.selectorText}
            {policy.tier ? ` · tier ${policy.tier}` : ""}
            {policy.order !== undefined ? ` · order ${policy.order}` : ""}
          </Span>
          {policy.rules.length === 0 ? (
            <Span $font={{ size: "s" }} $color="critical">
              No {policy.direction} rules: the selected pods {policy.direction === "ingress" ? "accept" : "send"} nothing{policy.isolates ? "" : " beyond what other policies allow"}.
            </Span>
          ) : (
            policy.rules.map((rule) => (
              <Span key={rule.index} $font={{ size: "s" }}>
                {rule.index + 1}. {rule.text}
                {rule.caveats.length > 0 && <Muted> ({rule.caveats.join("; ")})</Muted>}
              </Span>
            ))
          )}
          {policy.problems.map((problem) => (
            <Span key={problem} $font={{ size: "xs" }} $color="warning">
              {problem}
            </Span>
          ))}
        </Section>
      ))}
    </Div>
  );
});

const modeText = { kubernetes: "Kubernetes NetworkPolicy", cilium: "Cilium", calico: "Calico" } as const;

export const NetworkView = observer(({ clusterId }: { clusterId: string }) => {
  const model = useInject(networkModelInjectable)(clusterId);
  const detection = model.detection.get();
  const current = model.model.get();

  return (
    <Page>
      <PageHeader Icon={NetworkIcon} title="Network reachability" subtitle="What NetworkPolicy, Cilium and Calico policies let through, between pods, services and the outside.">
        <Stat label="policies" value={new Set(current.policies.map((policy) => netPolicyRefKey(policy.ref))).size} />
        <Stat label="pods" value={model.pods.get().length} />
      </PageHeader>
      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
        <ToneBadge tone="primary" label={`Evaluated with ${modeText[detection.mode]} semantics`} />
        {detection.cni && <Badge small label={`CNI: ${detection.cni}`} />}
      </Div>
      {detection.notes.map((note) => (
        <Notice key={note} tone={detection.enforcesNetworkPolicy === false ? "warning" : "notice"}>
          {note}
        </Notice>
      ))}
      <LabBanner clusterId={model.clusterId} />
      <LoadStatus snapshot={model.snapshot.get()} />
      <LightWeightTabs
        tabs={[
          { id: "simulate", label: "Simulator" },
          { id: "matrix", label: "Matrix" },
          { id: "coverage", label: "Coverage" },
          { id: "policies", label: "Policies" },
        ]}
        selected={model.state.subView.get()}
        onSelect={(view) => view && model.state.setSubView(view)}
      />
      {model.state.subView.get() === "simulate" && <Simulator model={model} />}
      {model.state.subView.get() === "matrix" && <Matrix model={model} />}
      {model.state.subView.get() === "coverage" && <Coverage model={model} />}
      {model.state.subView.get() === "policies" && <PolicyList model={model} />}
    </Page>
  );
});
