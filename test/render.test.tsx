/**
 * Renders every view outside Lens, against the minikube fixtures, with Lens's UI packages replaced
 * by plain-HTML stubs (test/stubs). Catches what throws while rendering, and writes each view's text
 * to $OUT for reading. Run with `node test/run.mjs render`.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { computed } from "mobx";
import { enableStaticRendering } from "mobx-react";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement } from "react";
import { clusterKindInjectable, type KindLoad } from "../src/data/cluster-kind.injectable";
import { NetworkView } from "../src/network/network-view";
import { networkStateInjectable } from "../src/network/network-state.injectable";
import { PolicyView } from "../src/policies/policy-view";
import { policyStateInjectable } from "../src/policies/policy-state.injectable";
import { clusterLabelInjectable } from "../src/cluster-label.injectable";
import { labAiInjectable } from "../src/lab/lab-ai.injectable";
import { openGovernanceViewInjectable } from "../src/navigation.injectable";
import { searchPickerStateInjectable } from "../src/ui/search-picker-state.injectable";
import { labPersistenceInjectable, type LabSaved } from "../src/lab/lab-persistence.injectable";
import { labStateInjectable } from "../src/lab/lab-state.injectable";
import { LabView } from "../src/lab/lab-view";
import { RbacView } from "../src/rbac/rbac-view";
import { rbacStateInjectable } from "../src/rbac/rbac-state.injectable";

enableStaticRendering(true);

const fixtures = process.env.FIXTURES!;
const out = process.env.OUT!;
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(fixtures, `${name}.json`), "utf8")).items as unknown[];

const sources: Record<string, unknown[]> = {
  pods: load("pods"),
  namespaces: load("namespaces"),
  services: load("services"),
  serviceAccounts: load("serviceaccounts"),
  roles: load("roles"),
  clusterRoles: load("clusterroles"),
  roleBindings: load("rolebindings"),
  clusterRoleBindings: load("clusterrolebindings"),
  networkPolicies: load("networkpolicies"),
  kyvernoClusterPolicies: load("clusterpolicies.kyverno.io"),
  kyvernoPolicies: load("policies.kyverno.io"),
  policyReports: load("policyreports.wgpolicyk8s.io"),
  clusterPolicyReports: load("clusterpolicyreports.wgpolicyk8s.io"),
  constraintTemplates: [
    {
      kind: "ConstraintTemplate",
      metadata: { name: "k8srequiredlabels", annotations: { description: "Requires resources to carry the labels the constraint names." } },
      spec: { crd: { spec: { names: { kind: "K8sRequiredLabels" } } }, targets: [{ target: "admission.k8s.gatekeeper.sh", rego: "package k8srequiredlabels\nviolation[{\"msg\": msg}] {\n  missing := {l | l := input.parameters.labels[_]; not input.review.object.metadata.labels[l]}\n  count(missing) > 0\n  msg := sprintf(\"missing labels: %v\", [missing])\n}" }] },
    },
  ],
  "constraint:K8sRequiredLabels": [
    {
      kind: "K8sRequiredLabels",
      metadata: { name: "namespaces-need-owner" },
      spec: { enforcementAction: "dryrun", match: { kinds: [{ apiGroups: [""], kinds: ["Namespace"] }], excludedNamespaces: ["kube-*"] }, parameters: { labels: ["owner"] } },
      status: { totalViolations: 2, violations: [{ kind: "Namespace", name: "default", message: "missing labels: {\"owner\"}", enforcementAction: "dryrun" }, { kind: "Namespace", name: "lademo", message: "missing labels: {\"owner\"}", enforcementAction: "dryrun" }] },
    },
  ],
};

// The lab's saved state, kept in memory instead of on disk.
const saved = new Map<string, LabSaved>();
const fakePersistence = {
  load: async (clusterId: string) => saved.get(clusterId) ?? { drafts: "", tests: "", aiCommand: "" },
  save: async (clusterId: string, value: LabSaved) => void saved.set(clusterId, value),
};

// Lens's AI tool selection, as if Claude Code were selected; nothing is run.
const fakeAi = {
  toolFor: () => computed(() => ({ name: "Claude Code", command: "claude -p {prompt}", custom: false })),
  generate: async () => {},
  ask: async () => {},
};

// Every search picker drawn, so a scenario can open their lists as a click would.
const pickers: { show: () => void; hide: () => void; type: () => void }[] = [];

// A container like Lens's: one instance per injectable and instantiation parameters.
const instances = new Map<unknown, (...params: unknown[]) => unknown>();
// "restricted" stands for a cluster whose credentials may list pods but not RBAC, as demo clusters often are.
const forbiddenOnRestricted = new Set(["roles", "clusterRoles", "roleBindings", "clusterRoleBindings"]);

const fakeLoader = (key: string) => {
  const clusterOf = key.slice(0, key.indexOf("|"));
  const watchKey = key.slice(key.indexOf("|") + 1);
  const items = sources[watchKey];

  if (clusterOf === "restricted" && forbiddenOnRestricted.has(watchKey)) {
    return computed((): KindLoad => ({ state: "failed", error: `${watchKey} is forbidden: User "system:serviceaccount:demo:demo" cannot list resource` }));
  }

  return computed((): KindLoad => (items ? { state: "ready", items } : { state: "absent" }));
};

const memoize = (factory: (...params: unknown[]) => unknown) => {
  const cache = new Map<string, unknown>();

  return (...params: unknown[]) => {
    const key = JSON.stringify(params);

    if (!cache.has(key)) cache.set(key, factory(...params));

    return cache.get(key);
  };
};

const di = {
  inject: (injectable: { instantiate: (di: unknown) => (...params: unknown[]) => unknown }) => {
    if ((injectable as unknown) === clusterKindInjectable) return memoize(fakeLoader as (...params: unknown[]) => unknown);
    if ((injectable as unknown) === labPersistenceInjectable) return () => fakePersistence;
    if ((injectable as unknown) === labAiInjectable) return () => fakeAi;
    if ((injectable as unknown) === openGovernanceViewInjectable) return () => async () => {};
    if ((injectable as unknown) === clusterLabelInjectable) return (id: string) => computed(() => id);
    if ((injectable as unknown) === searchPickerStateInjectable && !instances.has(injectable)) {
      const create = memoize(injectable.instantiate(di));

      instances.set(injectable, (...params: unknown[]) => {
        const picker = create(...params) as (typeof pickers)[number];

        if (!pickers.includes(picker)) pickers.push(picker);

        return picker;
      });
    }
    if (!instances.has(injectable)) instances.set(injectable, memoize(injectable.instantiate(di)));

    return instances.get(injectable)!;
  },
};

(globalThis as { __testDi?: unknown }).__testDi = di;

const clusterId = "minikube";
const rbac = (di.inject(rbacStateInjectable as never) as (id: string) => ReturnType<ReturnType<(typeof rbacStateInjectable)["instantiate"]>>)(clusterId);
const policies = (di.inject(policyStateInjectable as never) as (id: string) => ReturnType<ReturnType<(typeof policyStateInjectable)["instantiate"]>>)(clusterId);
const network = (di.inject(networkStateInjectable as never) as (id: string) => ReturnType<ReturnType<(typeof networkStateInjectable)["instantiate"]>>)(clusterId);

const textOf = (html: string) =>
  html
    .replace(/<(div|tr|h2|nav|p|section|pre|table)[^>]*>/g, "\n")
    .replace(/<\/(td|th)>/g, " | ")
    .replace(/<[^>]+>/g, "")
    .replace(/&gt;/g, ">")
    .replace(/&lt;/g, "<")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\n\s*\n+/g, "\n")
    .trim();

const results: { name: string; error?: unknown }[] = [];

const scenario = (name: string, render: () => ReactElement, expect: (text: string) => void = () => {}) => {
  try {
    const text = textOf(renderToStaticMarkup(render()));

    fs.writeFileSync(path.join(out, `${name}.txt`), text);
    expect(text);
    results.push({ name });
  } catch (error) {
    results.push({ name, error });
  }
};

// Permissions
scenario("rbac-list", () => <RbacView clusterId={clusterId} />, (text) => {
  assert.match(text, /Service account permissions/);
  assert.match(text, /argocd-application-controller/);
});

// The dashboard: a tile lists its accounts, and a second click lists them all again.
scenario("rbac-dashboard", () => <RbacView clusterId={clusterId} />, (text) => {
  assert.match(text, /Critical19 ?15 have running pods/);
  assert.match(text, /High13 ?3 have running pods/);
  assert.match(text, /No findings46/);
});

rbac.toggleRiskTile("critical");
scenario("rbac-dashboard-critical", () => <RbacView clusterId={clusterId} />, (text) => {
  assert.match(text, /Showing critical accounts/);
  assert.match(text, /argocd-application-controller/);
  assert.doesNotMatch(text, /coredns/);
});

rbac.toggleRiskTile("critical");
scenario("rbac-dashboard-cleared", () => <RbacView clusterId={clusterId} />, (text) => {
  assert.doesNotMatch(text, /Showing critical accounts/);
  assert.match(text, /coredns/);
});

rbac.select("ServiceAccount:argocd/argocd-application-controller");
rbac.setCanI({ verb: "create", resource: "pods/exec", namespace: "kube-system" });
scenario("rbac-admin-account", () => <RbacView clusterId={clusterId} />, (text) => {
  assert.match(text, /Full control/);
  assert.match(text, /ALLOWED/);
  assert.match(text, /Permission matrix/);
});

rbac.select("ServiceAccount:default/default");
rbac.setCanI({ verb: "list", resource: "secrets", namespace: "default" });
rbac.setMatrixScope("default");
scenario("rbac-default-account", () => <RbacView clusterId={clusterId} />, (text) => assert.match(text, /DENIED/));

rbac.setShowImplicit(true);
rbac.setMatrixAllRows(true);
scenario("rbac-default-account-everything", () => <RbacView clusterId={clusterId} />);

rbac.setSubView("who-can");
rbac.setWhoCan({ verb: "get", resource: "secrets", namespace: "kyverno" });
scenario("rbac-who-can", () => <RbacView clusterId={clusterId} />, (text) => assert.match(text, /subjects? can/));

rbac.setWhoCan({ includeSystem: true, resource: "/metrics", verb: "get", namespace: "" });
scenario("rbac-who-can-url", () => <RbacView clusterId={clusterId} />);

const restricted = (di.inject(rbacStateInjectable as never) as (id: string) => ReturnType<ReturnType<(typeof rbacStateInjectable)["instantiate"]>>)("restricted");

restricted.select("ServiceAccount:argocd/argocd-application-controller");
scenario("rbac-unreadable", () => <RbacView clusterId="restricted" />, (text) => {
  assert.match(text, /Permissions cannot be worked out on this cluster/);
  assert.match(text, /Its permissions are not known/);
  assert.doesNotMatch(text, /Full control/);
});

// Policies
scenario("policies-list", () => <PolicyView clusterId={clusterId} />, (text) => {
  assert.match(text, /Disallow Latest Tag/);
  assert.match(text, /namespaces-need-owner/);
});

policies.toggleExpanded("kyverno:ClusterPolicy:/disallow-latest-tag");
policies.toggleExpanded("gatekeeper:K8sRequiredLabels:/namespaces-need-owner");
scenario("policies-expanded", () => <PolicyView clusterId={clusterId} />, (text) => {
  assert.match(text, /must be not matching/);
  assert.match(text, /nexus-relay/);
  assert.match(text, /package k8srequiredlabels/);
});

policies.setSubView("simulate");
policies.setSimulation({ kind: "Pod", namespace: "nexus-relay", labels: "app=relay" });
scenario("policies-simulate-pod", () => <PolicyView clusterId={clusterId} />, (text) => assert.match(text, /Rejected unless it complies/));

// Opened while it holds Pod and nexus-relay, the lists still offer every kind and namespace.
pickers.length = 0;
renderToStaticMarkup(<PolicyView clusterId={clusterId} />);
pickers.forEach((picker) => picker.show());
scenario("policies-simulate-pickers-open", () => <PolicyView clusterId={clusterId} />, (text) => {
  assert.match(text, /Deploymentapps/);
  assert.match(text, /ClusterRoleBinding/);
  assert.match(text, /kube-system/);
  assert.match(text, /argocd/);
});

// Typing narrows them.
pickers.forEach((picker) => picker.type());
policies.setSimulation({ kind: "Stateful" });
scenario("policies-simulate-pickers-typed", () => <PolicyView clusterId={clusterId} />, (text) => {
  assert.match(text, /StatefulSet/);
  assert.doesNotMatch(text, /ClusterRoleBinding/);
});
pickers.forEach((picker) => picker.hide());

policies.setSimulation({ kind: "Namespace", namespace: "", operation: "CREATE" });
policies.setShowSkipped(true);
scenario("policies-simulate-namespace", () => <PolicyView clusterId={clusterId} />, (text) => assert.match(text, /reported unless it complies/));

policies.setSimulation({ kind: "Deployment", namespace: "kube-system" });
scenario("policies-simulate-excluded", () => <PolicyView clusterId={clusterId} />, (text) => assert.match(text, /No admission rule applies/));

policies.setSubView("violations");
scenario("policies-violations", () => <PolicyView clusterId={clusterId} />, (text) => assert.match(text, /latest/));

// Network
scenario("network-empty", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /Pick a source and a destination/));

const pod = (namespace: string, prefix: string) =>
  `pod:${namespace}/${(sources.pods as { metadata: { namespace: string; name: string } }[]).find((candidate) => candidate.metadata.namespace === namespace && candidate.metadata.name.startsWith(prefix))!.metadata.name}`;

network.setSource(pod("default", "podinfo"));
network.setDestination(pod("argocd", "argocd-dex-server"));
network.setPort("5556");
scenario("network-pod-denied", () => <NetworkView clusterId={clusterId} />, (text) => {
  assert.match(text, /DENIED/);
  assert.match(text, /argocd-dex-server-network-policy/);
});

network.setSource(pod("argocd", "argocd-server"));
scenario("network-pod-allowed", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /is allowed/));

network.setDestination("svc:argocd/argocd-redis");
scenario("network-service", () => <NetworkView clusterId={clusterId} />, (text) => {
  assert.match(text, /Backend argocd-redis/);
  assert.match(text, /DNS/);
});

network.setSource(pod("default", "podinfo"));
scenario("network-service-denied", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /No backend of argocd-redis is reachable/));

network.setSource("203.0.113.9");
network.setDestination(pod("flux-system", "source-controller"));
network.setPort("9090");
scenario("network-external", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /outside the cluster/));

network.setSource("svc:argocd/argocd-redis");
scenario("network-invalid-source", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /cannot start a flow/));

network.setSubView("matrix");
network.toggleMatrixNamespace("argocd");
network.toggleMatrixNamespace("flux-system");
scenario("network-matrix", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /argocd\/argocd-redis/));

network.setMatrixNamespaces([]);
scenario("network-matrix-default", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /3 of 21 shown/));

// All namespaces at once: every workload of minikube, none left out.
network.setMatrixNamespaces((sources.namespaces as { metadata: { name: string } }[]).map((namespace) => namespace.metadata.name));
scenario("network-matrix-all", () => <NetworkView clusterId={clusterId} />, (text) => {
  assert.match(text, /21 of 21 shown/);
  assert.match(text, /kube-system\/coredns/);
  assert.match(text, /argocd\/argocd-server/);
  assert.doesNotMatch(text, /left out/);
});

network.setMatrixNamespaces(["argocd", "flux-system"]);
network.setMatrixPortMode("fixed");
network.setMatrixPort("8080");
scenario("network-matrix-fixed", () => <NetworkView clusterId={clusterId} />);

network.setSubView("coverage");
scenario("network-coverage", () => <NetworkView clusterId={clusterId} />, (text) => {
  assert.match(text, /argocd/);
  assert.doesNotMatch(text, /flux-system/);
});

network.setCoverageHideSystem(false);
scenario("network-coverage-system", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /flux-system[^]*\(system\)/));

network.setSubView("policies");
scenario("network-policies", () => <NetworkView clusterId={clusterId} />, (text) => assert.match(text, /allow-scraping/));

// Policy lab
const lab = (di.inject(labStateInjectable as never) as (id: string) => ReturnType<ReturnType<(typeof labStateInjectable)["instantiate"]>>)(clusterId);

scenario("lab-empty", () => <LabView clusterId={clusterId} />, (text) => {
  assert.match(text, /Policy lab/);
  assert.match(text, /Generate with Claude Code/);
  assert.match(text, /Write or generate a policy/);
});

lab.setDrafts(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: default
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-team-label
spec:
  rules:
    - name: check-team
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        failureAction: Enforce
        message: Pods need a team label.
        pattern:
          metadata:
            labels:
              team: "?*"
---
this: is: not yaml
`);
lab.setTests(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:latest
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: tagged
  namespace: default
  labels:
    team: shop
spec:
  containers:
    - name: app
      image: nginx:1.27
`);
scenario("lab-results", () => <LabView clusterId={clusterId} />, (text) => {
  assert.match(text, /Draft policies, line \d+: Not valid YAML/);
  // The Deployment breaks the cluster's disallow-latest-tag and the draft's team label rule.
  assert.match(text, /REJECTED[^]*Deployment default\/web/);
  assert.match(text, /autogen-validate-image-tag/);
  assert.match(text, /autogen-check-team/);
  assert.match(text, /Pods need a team label/);
  // The tagged pod with a team label passes both.
  assert.match(text, /ADMITTED[^]*Pod default\/tagged/);
  // The draft default deny isolates it, and cuts DNS.
  assert.match(text, /isolated by NetworkPolicy default\/default-deny/);
  assert.match(text, /DNS: blocked/);
  // And would select the pods default runs today.
  assert.match(text, /default-deny: selects \d+ pods/);
  assert.match(text, /would fail/);
});

network.setSubView("simulate");
network.setSource("pod:default/web");
network.setDestination(pod("argocd", "argocd-server"));
network.setPort("8080");
scenario("network-with-lab", () => <NetworkView clusterId={clusterId} />, (text) => {
  assert.match(text, /Simulating with the policy lab/);
  assert.match(text, /DENIED/);
  assert.match(text, /default-deny/);
});

policies.setSubView("policies");
policies.setSearch("team");
scenario("policies-with-lab", () => <PolicyView clusterId={clusterId} />, (text) => {
  assert.match(text, /\[draft\]/);
  assert.match(text, /require-team-label/);
});

lab.setApplyDrafts(false);
scenario("network-lab-ignored", () => <NetworkView clusterId={clusterId} />, (text) => assert.doesNotMatch(text, /Simulating with the policy lab/));

let failed = 0;

for (const result of results) {
  if (result.error) {
    failed++;
    console.log(`✗ ${result.name}\n  ${String((result.error as Error).stack ?? result.error).split("\n").slice(0, 12).join("\n  ")}`);
  } else {
    console.log(`✓ ${result.name}`);
  }
}

console.log(`\n${results.length - failed}/${results.length} rendered`);
process.exit(failed ? 1 : 0);
