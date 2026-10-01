/** Sections in Lens's own details panels, summarising what the views say about one resource. */

import { DrawerItem, NoItemsDetailItem } from "@k8slens/details-panel-components";
import { buildDetailsPanelSectionBunch, type DetailsPanelSectionProps } from "@k8slens/details-panel-contracts";
import { ClickableDiv, Div, Span } from "@k8slens/element-components";
import { coreV1, podKind, serviceAccountKind } from "@k8slens/kubernetes-contracts";
import { useInject } from "@k8slens/use-inject";
import { observer } from "mobx-react";
import { inspectServiceAccountInjectable, simulateFromPodInjectable } from "./actions.injectable";
import { policiesSelecting } from "./engines/net/evaluate";
import { isImplicitGroupGrant } from "./engines/rbac";
import { netPolicyRefLabel } from "./engines/net/model";
import { toPodInfo } from "./engines/net/pods";
import { networkModelInjectable } from "./network/network-model.injectable";
import { rbacModelInjectable } from "./rbac/rbac-model.injectable";
import { ErrorBoundary, Muted, SeverityBadge } from "./ui/common";

const ServiceAccountPermissions = observer(({ resource, clusterId }: DetailsPanelSectionProps<typeof serviceAccountKind, typeof coreV1>) => {
  const model = useInject(rbacModelInjectable)(clusterId);
  const inspect = useInject(inspectServiceAccountInjectable)();
  const namespace = resource.metadata.namespace ?? "default";
  const account = model.accounts.get().find((candidate) => candidate.principal.namespace === namespace && candidate.principal.name === resource.metadata.name);

  const access = model.access.get();

  if (access.state === "reading") return <NoItemsDetailItem>Reading roles and bindings…</NoItemsDetailItem>;

  if (access.state === "unreadable") {
    return (
      <NoItemsDetailItem>
        Unknown: Lens's credentials for this cluster may not list {access.unreadable.map((entry) => entry.label.toLowerCase()).join(", ")}.
      </NoItemsDetailItem>
    );
  }

  if (!account) return <NoItemsDetailItem>{model.snapshot.get().loading ? "Reading service accounts…" : "Not found among the cluster's service accounts."}</NoItemsDetailItem>;

  return (
    <>
      <DrawerItem name="Risk">
        {account.worst ? <SeverityBadge severity={account.worst} /> : <Muted>nothing in the usual escalation paths</Muted>}
      </DrawerItem>
      {account.risks.slice(0, 4).map((risk) => (
        <DrawerItem key={risk.id} name="">
          <Span $font={{ size: "s" }}>
            <SeverityBadge severity={risk.severity} /> {risk.title} {risk.where === "all" ? "(cluster-wide)" : `(in ${risk.where.join(", ")})`}
          </Span>
        </DrawerItem>
      ))}
      <DrawerItem name="Bindings">{account.grants.filter((grant) => !isImplicitGroupGrant(grant)).length}</DrawerItem>
      <DrawerItem name="">
        <ClickableDiv $color="link" $onClick={() => void inspect(clusterId, namespace, resource.metadata.name)}>
          Show everything it can do
        </ClickableDiv>
      </DrawerItem>
    </>
  );
});

export const serviceAccountPermissionsSection = buildDetailsPanelSectionBunch({
  id: "real-governance-service-account-permissions",
  kind: serviceAccountKind,
  apiVersion: coreV1,
  title: "Permissions",
  orderNumber: 35,
  Component: (props: DetailsPanelSectionProps<typeof serviceAccountKind, typeof coreV1>) => (
    <ErrorBoundary label="Permissions">
      <ServiceAccountPermissions {...props} />
    </ErrorBoundary>
  ),
});

const PodNetwork = observer(({ resource, clusterId }: DetailsPanelSectionProps<typeof podKind, typeof coreV1>) => {
  const model = useInject(networkModelInjectable)(clusterId);
  const simulate = useInject(simulateFromPodInjectable)();
  const pod = toPodInfo(resource);

  if (model.snapshot.get().loading) return <NoItemsDetailItem>Reading network policies…</NoItemsDetailItem>;

  const current = model.model.get();
  const selecting = policiesSelecting(current, pod);
  const describe = (direction: "ingress" | "egress") => {
    const policies = selecting[direction];

    if (pod.hostNetwork) return <Muted>host network: pod policies do not apply</Muted>;
    if (policies.length === 0) return <Muted>open: no policy selects it</Muted>;

    return (
      <Div $flex={{ direction: "vertical", gap: "zero" }}>
        {policies.map((policy) => (
          <Span key={`${policy.ref.engine}/${netPolicyRefLabel(policy.ref)}`} $font={{ size: "s" }}>
            {netPolicyRefLabel(policy.ref)}
          </Span>
        ))}
      </Div>
    );
  };

  return (
    <>
      <DrawerItem name="Ingress">{describe("ingress")}</DrawerItem>
      <DrawerItem name="Egress">{describe("egress")}</DrawerItem>
      <DrawerItem name="">
        <ClickableDiv $color="link" $onClick={() => void simulate(clusterId, pod.namespace, pod.name)}>
          Check what it can reach
        </ClickableDiv>
      </DrawerItem>
    </>
  );
});

export const podNetworkSection = buildDetailsPanelSectionBunch({
  id: "real-governance-pod-network",
  kind: podKind,
  apiVersion: coreV1,
  title: "Network policy",
  orderNumber: 36,
  Component: (props: DetailsPanelSectionProps<typeof podKind, typeof coreV1>) => (
    <ErrorBoundary label="Network policy">
      <PodNetwork {...props} />
    </ErrorBoundary>
  ),
});
