import { Badge } from "@k8slens/badge";
import { ClickableDiv, Div, Span, Table, Td, Th, Tr } from "@k8slens/element-components";
import { CheckCircleIcon, ErrorIcon, InfoOutlineIcon, PeopleIcon, WarningIcon } from "@k8slens/icon";
import { TextInput } from "@k8slens/input-components";
import { LightWeightTabs } from "@k8slens/tabs-components";
import { useInject } from "@k8slens/use-inject";
import { observer } from "mobx-react";
import { describeRule, type Grant, scopeLabel } from "../engines/rbac";
import {
  Chips,
  Empty,
  Field,
  InlineCode,
  LoadStatus,
  Muted,
  Notice,
  Page,
  PageHeader,
  Picker,
  plural,
  Section,
  SeverityBadge,
  Stat,
  ToneBadge,
  VerdictBadge,
} from "../ui/common";
import styles from "../ui/governance.module.scss";
import { type AccountSummary, type RbacModel, rbacModelInjectable } from "./rbac-model.injectable";
import type { RiskFilter } from "./rbac-state.injectable";

const verbOptions = ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate", "approve", "use", "*"].map(
  (value) => ({ value }),
);

const GrantPath = ({ grant }: { grant: Grant }) => (
  <Span $font={{ size: "s" }}>
    {grant.binding.kind} <InlineCode>{grant.binding.namespace ? `${grant.binding.namespace}/` : ""}{grant.binding.name}</InlineCode> → {grant.role.kind}{" "}
    <InlineCode>{grant.role.name}</InlineCode>
    {!grant.roleExists && <ToneBadge tone="warning" label="role missing" tooltip="The binding names a role that does not exist: it grants nothing until it does." />}{" "}
    <Muted>
      ({scopeLabel(grant.scope)}, via {grant.via})
    </Muted>
  </Span>
);

/** Said wherever a permission would otherwise be shown: an unreadable role list makes every account look harmless. */
const AccessNotice = observer(({ model }: { model: RbacModel }) => {
  const access = model.access.get();

  if (access.state === "ready") return null;

  if (access.state === "reading") {
    return <Notice>Reading {access.waitingFor.map((label) => label.toLowerCase()).join(", ")}: permissions show once they arrive.</Notice>;
  }

  return (
    <Notice tone="critical">
      <Div $flex={{ direction: "vertical", gap: "xxs" }}>
        <Span $font={{ bold: true }}>
          Permissions cannot be worked out on this cluster: the credentials Lens connects with may not list{" "}
          {access.unreadable.map((entry) => entry.label.toLowerCase()).join(", ")}.
        </Span>
        <Span $font={{ size: "s" }}>
          Without them every account would look as if it could do nothing, so no account is rated. Reading permissions needs list on roles, clusterroles,
          rolebindings and clusterrolebindings of rbac.authorization.k8s.io.
        </Span>
      </Div>
    </Notice>
  );
});

/** What each tile stands for, in the words of the checks that put an account there. */
const riskTiles: readonly { risk: RiskFilter; label: string; Icon: typeof ErrorIcon; tone: "critical" | "warning" | "notice" | "grey40" | "success"; meaning: string }[] = [
  {
    risk: "critical",
    label: "Critical",
    Icon: ErrorIcon,
    tone: "critical",
    meaning: "Cluster-wide: full control, binding roles, reading secrets, minting tokens, impersonation, webhooks or node proxy",
  },
  { risk: "high", label: "High", Icon: WarningIcon, tone: "warning", meaning: "Those in some namespaces, or exec into pods, creating workloads, approving certificates" },
  { risk: "medium", label: "Medium", Icon: InfoOutlineIcon, tone: "notice", meaning: "Wildcard rules, persistent volumes, network policy changes or broad deletes" },
  { risk: "low", label: "Low", Icon: InfoOutlineIcon, tone: "grey40", meaning: "Network policy changes or deletes in some namespaces" },
  { risk: "none", label: "No findings", Icon: CheckCircleIcon, tone: "success", meaning: "Nothing in the usual escalation paths" },
];

/** How many accounts sit at each severity; a tile narrows the list to its accounts. */
const RiskDashboard = observer(({ model }: { model: RbacModel }) => {
  const known = model.access.get().state === "ready";
  const { bySeverity } = model.tally.get();
  const filter = model.state.riskFilter;

  return (
    <Div $className={styles.riskTiles} role="group" aria-label="Service accounts by risk">
      {riskTiles.map(({ risk, label, Icon, tone, meaning }) => {
        const counts = bySeverity[risk];
        const selected = filter.size === 1 && filter.has(risk);

        return (
          <ClickableDiv
            key={risk}
            $className={[styles.riskTile, { [styles.riskTileSelected]: selected }]}
            $padding={{ horizontal: "m", vertical: "s" }}
            $flex={{ direction: "vertical", gap: "xxs" }}
            $disabled={!known}
            $tooltip={selected ? `Showing ${label.toLowerCase()} accounts: click to show every account` : `${meaning}. Click to list them.`}
            aria-pressed={selected}
            $onClick={() => model.state.toggleRiskTile(risk)}
          >
            <Div $flex={{ direction: "horizontal", gap: "xs", verticalAlign: "center" }}>
              <Span $color={tone}>
                <Icon $size="s" />
              </Span>
              <Span $font={{ size: "s", bold: true }}>{label}</Span>
            </Div>
            <Span $font={{ size: "3xl", bold: "600" }} $color="textHighlight">
              {known ? counts.accounts : "?"}
            </Span>
            <Span $font={{ size: "xs" }} $color="textMuted">
              {known ? (counts.accounts === 0 ? "no accounts" : counts.withPods === 0 ? "no running pod uses them" : `${plural(counts.withPods, "has", "have")} running pods`) : "permissions unknown"}
            </Span>
          </ClickableDiv>
        );
      })}
    </Div>
  );
});

const filterWords: Record<RiskFilter, string> = { critical: "critical", high: "high", medium: "medium", low: "low", none: "no-finding" };

const AccountRow = observer(({ model, account }: { model: RbacModel; account: AccountSummary }) => {
  const selected = model.state.selected.get() === account.key;

  return (
    <ClickableDiv
      $className={[styles.listRow, { [styles.listRowSelected]: selected }]}
      $padding={{ horizontal: "s", vertical: "xs" }}
      $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center" }}
      $onClick={() => model.state.select(account.key)}
    >
      <Div $flex={{ direction: "vertical", gap: "zero" }} $flexChild="shrinkable">
        <Span $font={{ bold: selected, textOverflow: "ellipsis", noWrap: true }}>{account.principal.name}</Span>
        <Span $font={{ size: "xs", textOverflow: "ellipsis", noWrap: true }} $color="textMuted">
          {account.principal.namespace} · {plural(account.pods.length, "pod")}
        </Span>
      </Div>
      {model.access.get().state !== "ready" ? <Badge small label="?" $tooltip="Its permissions are not known" /> : account.worst && <SeverityBadge severity={account.worst} />}
    </ClickableDiv>
  );
});

const AccountList = observer(({ model }: { model: RbacModel }) => {
  const accounts = model.visibleAccounts.get();

  return (
    <Section title={`Service accounts (${accounts.length})`}>
      <TextInput type="search" placeholder="Filter by name" value={model.state.search.get()} onChange={(event) => model.state.setSearch(event.target.value)} />
      <Picker
        value={model.state.namespace.get()}
        onChange={model.state.setNamespace}
        options={model.namespaces.get().map((value) => ({ value }))}
        placeholder="Every namespace"
      />
      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
        <Chips
          options={[{ id: "risky", label: "Critical and high only" }]}
          isSelected={() => model.state.riskFilter.size === 2 && model.state.riskFilter.has("critical") && model.state.riskFilter.has("high")}
          onToggle={() =>
            model.state.showRisks(model.state.riskFilter.size === 2 && model.state.riskFilter.has("critical") && model.state.riskFilter.has("high") ? [] : ["critical", "high"])
          }
        />
        {model.state.riskFilter.size > 0 && (
          <>
            <Muted>
              Showing {[...model.state.riskFilter].map((risk) => filterWords[risk]).join(" and ")} accounts
            </Muted>
            <ClickableDiv $color="link" $onClick={() => model.state.showRisks([])}>
              Show all
            </ClickableDiv>
          </>
        )}
      </Div>
      <Div $className={styles.list} $flex={{ direction: "vertical", gap: "zero" }}>
        {accounts.map((account) => (
          <AccountRow key={account.key} model={model} account={account} />
        ))}
        {accounts.length === 0 && <Empty>No service account matches.</Empty>}
      </Div>
    </Section>
  );
});

const Risks = observer(({ account }: { account: AccountSummary }) => (
  <Section title="What makes this account risky">
    {account.risks.length === 0 && <Muted>Nothing in the usual escalation paths: no secrets, exec, RBAC changes, impersonation or wildcards.</Muted>}
    {account.risks.map((risk) => (
      <Div key={risk.id} $flex={{ direction: "vertical", gap: "xxs" }} $padding={{ vertical: "xs" }} $border={{ color: "borderPrimary", width: "xxs", exceptLast: true, radius: "zero" }}>
        <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
          <SeverityBadge severity={risk.severity} />
          <Span $font={{ bold: true }}>{risk.title}</Span>
          <Muted>{risk.where === "all" ? "in every namespace" : `in ${risk.where.join(", ")}`}</Muted>
        </Div>
        <Span $font={{ size: "s" }}>{risk.detail}</Span>
        {risk.grants.slice(0, 3).map((grant) => (
          <GrantPath key={`${grant.binding.kind}/${grant.binding.namespace}/${grant.binding.name}`} grant={grant} />
        ))}
        {risk.grants.length > 3 && <Muted>and {plural(risk.grants.length - 3, "more binding")}</Muted>}
      </Div>
    ))}
  </Section>
));

const CanI = observer(({ model }: { model: RbacModel }) => {
  const form = model.state.canI;
  const result = model.canI.get();

  return (
    <Section title="Can it…?">
      <Div $flex={{ direction: "horizontal", gap: "s", wrap: true }}>
        <Field label="Verb">
          <Picker value={form.verb} onChange={(verb) => model.state.setCanI({ verb })} options={verbOptions} />
        </Field>
        <Field label="Resource, or a /path" grow>
          <Picker
            value={form.resource}
            onChange={(resource) => model.state.setCanI({ resource })}
            options={model.knownResources.get().map((value) => ({ value }))}
            placeholder="pods/exec, deployments.apps, /metrics"
          />
        </Field>
        <Field label="Namespace (empty: cluster-wide)">
          <Picker value={form.namespace} onChange={(namespace) => model.state.setCanI({ namespace })} options={model.namespaces.get().map((value) => ({ value }))} />
        </Field>
        <Field label="Name (optional)">
          <TextInput value={form.name} onChange={(event) => model.state.setCanI({ name: event.target.value })} />
        </Field>
      </Div>
      {result && (
        <Div $flex={{ direction: "vertical", gap: "xs" }}>
          <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center" }}>
            <VerdictBadge allowed={result.allowed} />
            <Span>
              {result.allowed
                ? `${plural(result.matches.length, "rule")} grant${result.matches.length === 1 ? "s" : ""} it:`
                : result.request.type === "resource" && !result.request.namespace
                  ? "No cluster-wide grant covers it. A namespace may still allow it: pick one above."
                  : "No rule of any role bound to this account covers it."}
            </Span>
          </Div>
          {result.matches.map(({ grant, rule }, index) => (
            <Div key={index} $flex={{ direction: "vertical", gap: "zero" }} $padding={{ left: "m" }}>
              <InlineCode>{describeRule(rule)}</InlineCode>
              <GrantPath grant={grant} />
            </Div>
          ))}
        </Div>
      )}
    </Section>
  );
});

const Bindings = observer(({ model }: { model: RbacModel }) => {
  const grants = model.visibleGrants.get();
  const implicit = model.implicitGrantCount.get();

  return (
    <Section
      title={`Bindings that reach it (${grants.length})`}
      actions={
        implicit > 0 ? (
          <Chips
            options={[
              {
                id: "implicit",
                label: `Show grants every account has (${implicit})`,
                tooltip: "Bindings to system:authenticated and system:serviceaccounts",
              },
            ]}
            isSelected={() => model.state.showImplicit.get()}
            onToggle={() => model.state.setShowImplicit(!model.state.showImplicit.get())}
          />
        ) : undefined
      }
    >
      {grants.length === 0 && <Muted>No binding names this account, nor a group it is in beyond the ones every account is in.</Muted>}
      {grants.map((grant) => (
        <Div key={`${grant.binding.kind}/${grant.binding.namespace}/${grant.binding.name}`} $flex={{ direction: "vertical", gap: "xxs" }} $padding={{ vertical: "xs" }}>
          <GrantPath grant={grant} />
          <Div $flex={{ direction: "vertical", gap: "zero" }} $padding={{ left: "m" }}>
            {grant.rules.map((rule, index) => (
              <Span key={index} $font={{ size: "s" }}>
                <InlineCode>{describeRule(rule)}</InlineCode>
              </Span>
            ))}
          </Div>
        </Div>
      ))}
    </Section>
  );
});

const levelClass = { all: styles.permAll, some: styles.permSome, none: styles.permNone } as const;

const Matrix = observer(({ model }: { model: RbacModel }) => {
  const rows = model.matrix.get();
  const scope = model.state.matrixScope.get();

  return (
    <Section
      title="Permission matrix"
      actions={
        <>
          <Chips
            options={[{ id: "cluster", label: "Cluster-wide" }]}
            isSelected={() => scope === "cluster"}
            onToggle={() => model.state.setMatrixScope("cluster")}
          />
          <Div $className={styles.namespaceBox}>
            <Picker
              value={scope === "cluster" ? "" : scope}
              onChange={(value) => model.state.setMatrixScope(value.trim() || "cluster")}
              options={model.namespaces.get().map((value) => ({ value }))}
              placeholder="In namespace…"
            />
          </Div>
          <Chips
            options={[{ id: "all", label: "Show resources it cannot touch" }]}
            isSelected={() => model.state.matrixAllRows.get()}
            onToggle={() => model.state.setMatrixAllRows(!model.state.matrixAllRows.get())}
          />
        </>
      }
    >
      <Muted>
        {scope === "cluster"
          ? "Solid: in every namespace (or cluster-scoped). Outlined: only in some namespaces — rest on it to see which."
          : `What it may do in namespace ${scope}, through cluster-wide and namespace bindings together.`}
      </Muted>
      {rows.length === 0 ? (
        <Empty>It may do none of these.</Empty>
      ) : (
        <Div $overflow="auto">
          <Table $className={styles.matrix}>
            <thead>
              <Tr>
                <Th />
                {model.matrixVerbs.map((verb) => (
                  <Th key={verb}>{verb}</Th>
                ))}
              </Tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <Tr key={row.label}>
                  <Th $className={styles.rowHead}>{row.label}</Th>
                  {row.cells.map((cell) => (
                    <Td
                      key={cell.verb}
                      $className={[styles.permCell, levelClass[cell.level]]}
                      $tooltip={
                        cell.level === "none"
                          ? `Cannot ${cell.verb} ${row.label}`
                          : cell.level === "all"
                            ? `Can ${cell.verb} ${row.label}${row.resource.namespaced && scope === "cluster" ? " in every namespace" : ""}`
                            : `Can ${cell.verb} ${row.label} in ${cell.namespaces.join(", ")}`
                      }
                    />
                  ))}
                </Tr>
              ))}
            </tbody>
          </Table>
        </Div>
      )}
    </Section>
  );
});

const NonResource = observer(({ model }: { model: RbacModel }) => {
  const rules = model.nonResourceRules.get();

  if (rules.length === 0) return null;

  return (
    <Section title="Non-resource URLs">
      {rules.map(({ grant, rule }, index) => (
        <Div key={index} $flex={{ direction: "vertical", gap: "zero" }}>
          <InlineCode>{describeRule(rule)}</InlineCode>
          <GrantPath grant={grant} />
        </Div>
      ))}
    </Section>
  );
});

const AccountDetails = observer(({ model }: { model: RbacModel }) => {
  const account = model.selected.get();

  if (!account) {
    return (
      <Section>
        <Empty>Pick a service account to see what it can do. The riskiest are at the top.</Empty>
      </Section>
    );
  }

  const known = model.access.get().state === "ready";

  return (
    <Div $flex={{ direction: "vertical", gap: "m" }}>
      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
        <Span $font={{ size: "l", bold: true }}>
          {account.principal.namespace}/{account.principal.name}
        </Span>
        {known && account.worst && <SeverityBadge severity={account.worst} />}
        <Badge small label={plural(account.pods.length, "running pod")} $tooltip={account.pods.map((pod) => pod.metadata.name).join(", ") || "No pod runs as it"} />
        <Badge
          small
          label={account.automount ? "token auto-mounted" : "token not auto-mounted"}
          $tooltip="automountServiceAccountToken of the service account; a pod may still override it"
        />
      </Div>
      {account.pods.length > 0 && account.worst && (account.worst === "critical" || account.worst === "high") && (
        <Notice tone="warning">
          {plural(account.pods.length, "pod")} run as this account, so anyone who can exec into one of them can act with its permissions.
        </Notice>
      )}
      {known ? (
        <>
          <Risks account={account} />
          <CanI model={model} />
          <Matrix model={model} />
          <Bindings model={model} />
          <NonResource model={model} />
        </>
      ) : (
        <Muted>Its permissions are not known: see above.</Muted>
      )}
    </Div>
  );
});

const WhoCan = observer(({ model }: { model: RbacModel }) => {
  const form = model.state.whoCan;
  const result = model.whoCan.get();

  return (
    <Div $flex={{ direction: "vertical", gap: "m" }}>
      <Section title="Who can…?">
        <Div $flex={{ direction: "horizontal", gap: "s", wrap: true, verticalAlign: "bottom" }}>
          <Field label="Verb">
            <Picker value={form.verb} onChange={(verb) => model.state.setWhoCan({ verb })} options={verbOptions} />
          </Field>
          <Field label="Resource, or a /path" grow>
            <Picker
              value={form.resource}
              onChange={(resource) => model.state.setWhoCan({ resource })}
              options={model.knownResources.get().map((value) => ({ value }))}
              placeholder="secrets, pods/exec, clusterrolebindings"
            />
          </Field>
          <Field label="Namespace (empty: in every namespace)">
            <Picker value={form.namespace} onChange={(namespace) => model.state.setWhoCan({ namespace })} options={model.namespaces.get().map((value) => ({ value }))} />
          </Field>
          <Chips
            options={[{ id: "system", label: "Include system identities", tooltip: "kube-system accounts and system: users and groups" }]}
            isSelected={() => form.includeSystem}
            onToggle={() => model.state.setWhoCan({ includeSystem: !form.includeSystem })}
          />
        </Div>
        <Muted>Service accounts, plus every user and group a binding names. Members of groups are not known to the cluster, so a group stands for all of them.</Muted>
      </Section>
      {result && model.access.get().state === "ready" && (
        <Section title={`${plural(result.entries.length, "subject")} can`}>
          {result.entries.length === 0 ? (
            <Empty>Nobody{form.includeSystem ? "" : " outside the system identities"}.</Empty>
          ) : (
            <Table $className={styles.table}>
              <thead>
                <Tr>
                  <Th>Subject</Th>
                  <Th>Through</Th>
                </Tr>
              </thead>
              <tbody>
                {result.entries.map((entry) => (
                  <Tr key={`${entry.principal.type}:${entry.label}`}>
                    <Td>
                      <Div $flex={{ direction: "horizontal", gap: "xs", verticalAlign: "center" }}>
                        <Badge small label={entry.principal.type} />
                        {entry.principal.type === "ServiceAccount" ? (
                          <ClickableDiv
                            $color="link"
                            $tooltip="Show this account's permissions"
                            $onClick={() => {
                              if (entry.principal.type === "ServiceAccount") model.state.focusServiceAccount(entry.principal.namespace, entry.principal.name);
                            }}
                          >
                            {entry.label}
                          </ClickableDiv>
                        ) : (
                          <Span>{entry.label}</Span>
                        )}
                      </Div>
                    </Td>
                    <Td>
                      <Div $flex={{ direction: "vertical", gap: "zero" }}>
                        {entry.matches.slice(0, 3).map(({ grant }, index) => (
                          <GrantPath key={index} grant={grant} />
                        ))}
                      </Div>
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
        </Section>
      )}
    </Div>
  );
});

export const RbacView = observer(({ clusterId }: { clusterId: string }) => {
  const model = useInject(rbacModelInjectable)(clusterId);
  const tally = model.tally.get();

  return (
    <Page>
      <PageHeader Icon={PeopleIcon} title="Service account permissions" subtitle="Effective RBAC of every service account: its bindings, the roles they grant, and the groups every token is in.">
        <Stat label="accounts" value={tally.accounts} />
      </PageHeader>
      <LoadStatus snapshot={model.snapshot.get()} />
      <AccessNotice model={model} />
      <RiskDashboard model={model} />
      <LightWeightTabs
        tabs={[
          { id: "accounts", label: "Service accounts" },
          { id: "who-can", label: "Who can…?" },
        ]}
        selected={model.state.subView.get()}
        onSelect={(view) => view && model.state.setSubView(view)}
      />
      {model.state.subView.get() === "accounts" ? (
        <Div $className={styles.split}>
          <AccountList model={model} />
          <AccountDetails model={model} />
        </Div>
      ) : (
        <WhoCan model={model} />
      )}
    </Page>
  );
});
