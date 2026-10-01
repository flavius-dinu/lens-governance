/**
 * Engine tests, run outside Lens: `node test/run.mjs`. The minikube fixtures are live cluster data
 * saved with kubectl; FIXTURES points at them. Synthetic fixtures cover what no cluster here runs.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { authorize, grantsOf, indexRbac, parseResource, risksOf, type Principal } from "../src/engines/rbac";
import { parseCalicoSelector } from "../src/engines/net/calico-selector";
import { cidrContains, inBlock } from "../src/engines/net/ip";
import { buildNetworkModel, detectCni } from "../src/engines/net/build";
import { evaluateFlow, evaluateServiceFlow, type NetworkModel } from "../src/engines/net/evaluate";
import { toPodInfo, toServiceInfo } from "../src/engines/net/pods";
import type { Endpoint, PodInfo } from "../src/engines/net/model";
import { describePattern, normalizeKyvernoCelPolicy, normalizeKyvernoException, normalizeKyvernoPolicy, withAutogenRules } from "../src/engines/policies/kyverno";
import { checkKyvernoRule, parseDuration, parseQuantity, stringPatternMatches } from "../src/engines/policies/check";
import { normalizeConstraint, summarizeTemplate } from "../src/engines/policies/gatekeeper";
import { resultsOfReport, tally } from "../src/engines/policies/reports";
import { simulate } from "../src/engines/policies/simulate";
import type { SimulationTarget } from "../src/engines/policies/model";
import { matchesSelector } from "../src/engines/labels";
import { filterOptions, type SearchOption } from "../src/ui/search-filter";
import { overlay, parseManifests, podOfWorkload } from "../src/engines/lab/manifests";
import { commandLineFor, extractYaml, headlessCommandFor } from "../src/engines/lab/prompt";

const results: { name: string; error?: unknown }[] = [];

const test = (name: string, body: () => void) => {
  try {
    body();
    results.push({ name });
  } catch (error) {
    results.push({ name, error });
  }
};

const fixtures = process.env.FIXTURES!;
const load = (name: string) => JSON.parse(fs.readFileSync(path.join(fixtures, `${name}.json`), "utf8")).items as any[];

// ---------------------------------------------------------------------------------------------
// Basics
// ---------------------------------------------------------------------------------------------

test("search picker: every word matches somewhere, a fresh pick shows everything", () => {
  const options: SearchOption[] = [
    { value: "pod:argocd/argocd-server-7d9", kind: "Pod", name: "argocd-server-7d9", group: "argocd", detail: "Deployment argocd-server · ports 8080/TCP" },
    { value: "pod:argocd/argocd-redis-5f", kind: "Pod", name: "argocd-redis-5f", group: "argocd", detail: "Deployment argocd-redis · ports 6379/TCP" },
    { value: "svc:default/web", kind: "Service", name: "web", group: "default", detail: "ClusterIP · 80/TCP" },
  ];

  assert.equal(filterOptions(options, "", "").length, 3);
  assert.deepEqual(filterOptions(options, "argo 6379", "").map((option) => option.name), ["argocd-redis-5f"]);
  assert.deepEqual(filterOptions(options, "service", "").map((option) => option.name), ["web"]);
  assert.equal(filterOptions(options, "pod:argocd/argocd-server-7d9", "pod:argocd/argocd-server-7d9").length, 3);
  assert.equal(filterOptions(options, "10.0.0.1", "10.0.0.1").length, 0);
});

test("lab: manifests are read, sorted by role, and a broken one does not hide the rest", () => {
  const { documents, errors } = parseManifests(
    [
      "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: { name: deny }\nspec: { podSelector: {} }",
      "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata: { name: p }\nspec: { rules: [] }",
      "kind: [broken",
      "apiVersion: apps/v1\nkind: Deployment\nmetadata: { name: web, namespace: shop }\nspec: { template: { metadata: { labels: { app: web } }, spec: { containers: [{ name: c, image: x, ports: [{ containerPort: 80 }] }] } } }",
      "# only a comment",
      "apiVersion: v1\nkind: List\nitems:\n  - { apiVersion: v1, kind: Namespace, metadata: { name: shop, labels: { team: a } } }",
    ].join("\n---\n"),
    "drafts",
  );

  assert.deepEqual(documents.map((document) => `${document.role}:${document.kind}:${document.namespace ?? "-"}/${document.name}`), [
    "network-policy:NetworkPolicy:default/deny",
    "admission-policy:ClusterPolicy:-/p",
    "workload:Deployment:shop/web",
    "namespace:Namespace:-/shop",
  ]);
  assert.equal(errors.length, 1);
  assert.equal(errors[0]!.line, 11);

  const pod = toPodInfo(podOfWorkload(documents[2]!));
  assert.equal(pod.namespace, "shop");
  assert.deepEqual(pod.labels, { app: "web" });
  assert.equal(pod.ports[0]!.port, 80);

  // A draft stands in for the cluster's resource of the same kind, namespace and name.
  const merged = overlay([{ metadata: { name: "deny", namespace: "default" }, spec: { old: true } }, { metadata: { name: "keep", namespace: "default" } }], [documents[0]!.raw], (item: any) => ({ kind: "NetworkPolicy", ...item }));
  assert.deepEqual(merged.map((item: any) => `${item.metadata.name}:${item.spec?.old ? "old" : "new"}`), ["keep:new", "deny:new"]);
});

test("lab: YAML out of an AI answer, and the command that asks for it", () => {
  assert.equal(extractYaml("Here you go:\n```yaml\nkind: A\n```\nand\n```\nkind: B\n```"), "kind: A\n---\nkind: B");
  assert.equal(extractYaml("Sure!\napiVersion: v1\nkind: Pod"), "apiVersion: v1\nkind: Pod");
  assert.equal(headlessCommandFor("claude-code", "Claude Code"), "claude -p {prompt}");
  assert.equal(headlessCommandFor("some-tool", "Some Tool"), undefined);
  assert.equal(commandLineFor("claude -p {prompt}", "'a $& b'"), "claude -p 'a $& b' </dev/null 2>/dev/null");
  assert.equal(commandLineFor("my-ai", "'q'"), "my-ai 'q' </dev/null 2>/dev/null");
});

test("CIDR matching, v4 and v6", () => {
  assert.ok(cidrContains("10.244.0.0/16", "10.244.1.236"));
  assert.ok(!cidrContains("10.244.0.0/16", "10.245.0.1"));
  assert.ok(cidrContains("0.0.0.0/0", "8.8.8.8"));
  assert.ok(cidrContains("8.8.8.8", "8.8.8.8"));
  assert.ok(cidrContains("2001:db8::/32", "2001:db8:1::5"));
  assert.ok(!cidrContains("2001:db8::/32", "2001:db9::1"));
  assert.ok(cidrContains("::ffff:10.0.0.0/104", "::ffff:10.1.2.3"));
  assert.ok(!cidrContains("10.0.0.0/8", "2001:db8::1"));
  assert.ok(inBlock("10.0.0.0/8", ["10.1.0.0/16"], "10.2.0.1"));
  assert.ok(!inBlock("10.0.0.0/8", ["10.1.0.0/16"], "10.1.0.1"));
});

test("label selectors", () => {
  const labels = { app: "web", tier: "front" };

  assert.ok(matchesSelector({}, labels));
  assert.ok(matchesSelector({ matchLabels: { app: "web" } }, labels));
  assert.ok(!matchesSelector({ matchLabels: { app: "db" } }, labels));
  assert.ok(matchesSelector({ matchExpressions: [{ key: "tier", operator: "In", values: ["front", "back"] }] }, labels));
  assert.ok(matchesSelector({ matchExpressions: [{ key: "legacy", operator: "DoesNotExist" }] }, labels));
  assert.ok(!matchesSelector({ matchExpressions: [{ key: "app", operator: "NotIn", values: ["web"] }] }, labels));
});

test("Calico selectors", () => {
  const labels = { app: "web", tier: "front", "projectcalico.org/namespace": "shop" };

  assert.ok(parseCalicoSelector("all()")(labels));
  assert.ok(parseCalicoSelector("app == 'web' && has(tier)")(labels));
  assert.ok(!parseCalicoSelector("app == 'web' && !has(tier)")(labels));
  assert.ok(parseCalicoSelector("tier in {'front', 'back'}")(labels));
  assert.ok(parseCalicoSelector("role not in {'db'}")(labels));
  assert.ok(parseCalicoSelector("role != 'db'")(labels));
  assert.ok(parseCalicoSelector("(app == 'db') || (app starts with 'we')")(labels));
  assert.ok(parseCalicoSelector(`projectcalico.org/namespace == "shop"`)(labels));
  assert.ok(!parseCalicoSelector("app contains 'x'")(labels));
  assert.throws(() => parseCalicoSelector("app = 'web'"));
});

// ---------------------------------------------------------------------------------------------
// RBAC, against minikube
// ---------------------------------------------------------------------------------------------

const rbac = indexRbac({
  roles: load("roles"),
  clusterRoles: load("clusterroles"),
  roleBindings: load("rolebindings"),
  clusterRoleBindings: load("clusterrolebindings"),
});

const sa = (namespace: string, name: string): Principal => ({ type: "ServiceAccount", namespace, name });

test("parseResource", () => {
  assert.deepEqual(parseResource("pods/log"), { group: "", resource: "pods", subresource: "log" });
  assert.deepEqual(parseResource("deployments"), { group: "apps", resource: "deployments", subresource: undefined });
  assert.deepEqual(parseResource("deployments.apps"), { group: "apps", resource: "deployments", subresource: undefined });
  assert.deepEqual(parseResource("networking.k8s.io/ingresses"), { group: "networking.k8s.io", resource: "ingresses", subresource: undefined });
  assert.deepEqual(parseResource("certificates.cert-manager.io"), { group: "cert-manager.io", resource: "certificates", subresource: undefined });
});

test("default service account gets only what every account gets", () => {
  const grants = grantsOf(rbac, sa("default", "default"));

  assert.ok(grants.every((grant) => grant.via.startsWith("group ")), JSON.stringify(grants.map((grant) => grant.binding.name)));
  assert.equal(authorize(grants, { type: "resource", verb: "list", apiGroup: "", resource: "secrets", namespace: "default" }).allowed, false);
  assert.equal(authorize(grants, { type: "nonResource", verb: "get", path: "/version" }).allowed, true);
});

test("argocd application controller is cluster admin, and flagged", () => {
  const grants = grantsOf(rbac, sa("argocd", "argocd-application-controller"));
  const risks = risksOf(grants);

  assert.ok(authorize(grants, { type: "resource", verb: "delete", apiGroup: "apps", resource: "deployments", namespace: "kube-system" }).allowed);
  assert.equal(risks[0]?.severity, "critical");
  assert.ok(risks.some((risk) => risk.id === "full-admin"));
});

// Ground truth for the RBAC engine: the API server's own answers, captured with
// `kubectl auth can-i --as` into can-i.json by test/can-i.sh.
test("agrees with kubectl auth can-i", () => {
  const file = path.join(fixtures, "can-i.json");

  if (!fs.existsSync(file)) return;

  const cases = JSON.parse(fs.readFileSync(file, "utf8")) as {
    sa: string;
    verb: string;
    resource: string;
    namespace?: string;
    subresource?: string;
    expected: boolean;
  }[];
  const disagreements: string[] = [];

  for (const entry of cases) {
    const [namespace, name] = entry.sa.split("/") as [string, string];
    const parsed = parseResource(entry.resource)!;
    const request = {
      type: "resource" as const,
      verb: entry.verb,
      apiGroup: parsed.group,
      resource: parsed.resource,
      subresource: entry.subresource ?? undefined,
      namespace: entry.namespace ?? undefined,
    };
    const answer = authorize(grantsOf(rbac, sa(namespace, name)), request).allowed;

    if (answer !== entry.expected) {
      disagreements.push(
        `${entry.sa} ${entry.verb} ${entry.resource}${entry.subresource ? `/${entry.subresource}` : ""} -n ${entry.namespace ?? "(cluster)"}: kubectl ${entry.expected}, engine ${answer}`,
      );
    }
  }

  assert.equal(disagreements.length, 0, `${disagreements.length}/${cases.length} disagree:\n${disagreements.slice(0, 30).join("\n")}`);
  console.log(`  (${cases.length} can-i cases agree)`);
});

// ---------------------------------------------------------------------------------------------
// Kyverno, against minikube
// ---------------------------------------------------------------------------------------------

const target = (overrides: Partial<SimulationTarget>): SimulationTarget => ({
  kind: "Pod",
  group: "",
  resource: "pods",
  namespace: "default",
  namespaceLabels: {},
  labels: {},
  operation: "CREATE",
  ...overrides,
});

const clusterPolicies = load("clusterpolicies.kyverno.io").map(normalizeKyvernoPolicy);

test("rule-level failureAction beats the policy's Audit", () => {
  const policy = clusterPolicies.find((candidate) => candidate.ref.name === "disallow-latest-tag")!;

  assert.equal(policy.title, "Disallow Latest Tag");
  assert.ok(policy.rules.filter((rule) => !rule.autogen).every((rule) => rule.effect === "enforce"));
});

test("pattern explanation", () => {
  assert.deepEqual(describePattern({ spec: { containers: [{ image: "!*:latest" }] } }), ["`spec.containers[*].image` must be not matching `*:latest`"]);
  assert.deepEqual(describePattern({ metadata: { labels: { "app.kubernetes.io/name": "?*" } } }), [
    "`metadata.labels.app.kubernetes.io/name` must be set to a non-empty value",
  ]);

  const lines = describePattern({ spec: { "=(hostNetwork)": false, containers: [{ "X(securityContext)": null, "(name)": "nginx*", resources: { limits: { memory: "<=1Gi" } } }] } });

  assert.equal(lines[0], "Only when `spec.containers[*].name` is matching `nginx*`:");
  assert.ok(lines.includes("  If `spec.hostNetwork` is set, it must be `false`"));
  assert.ok(lines.includes("  `spec.containers[*].securityContext` must not be set"));
  assert.ok(lines.includes("  `spec.containers[*].resources.limits.memory` must be at most 1Gi"));
});

test("simulation: who the policy applies to", () => {
  const context = { policies: clusterPolicies, exceptions: [], gatekeeperExcludedNamespaces: [] };

  const pod = simulate(context, target({ namespace: "nexus-relay" }));

  assert.deepEqual(pod.byEffect.enforce.map((entry) => entry.rule.name).sort(), ["require-image-tag", "validate-image-tag"]);

  const system = simulate(context, target({ namespace: "kube-system" }));

  assert.equal(system.applicable.length, 0);
  assert.ok(system.skipped.some((entry) => entry.reason.startsWith("excluded")));

  const deployment = simulate(context, target({ kind: "Deployment", group: "apps", resource: "deployments" }));

  assert.deepEqual(deployment.applicable.map((entry) => entry.rule.name).sort(), ["autogen-require-image-tag", "autogen-validate-image-tag"]);

  const cronJob = simulate(context, target({ kind: "CronJob", group: "batch", resource: "cronjobs" }));

  assert.equal(cronJob.applicable.length, 2);

  const service = simulate(context, target({ kind: "Service", resource: "services" }));

  assert.equal(service.applicable.length, 0);
});

test("policy exceptions exempt the named rules", () => {
  const exception = normalizeKyvernoException({
    metadata: { name: "relay-may-use-latest", namespace: "nexus-relay" },
    spec: {
      exceptions: [{ policyName: "disallow-latest-tag", ruleNames: ["validate-image-tag", "autogen-validate-image-tag"] }],
      match: { any: [{ resources: { kinds: ["Pod", "Deployment"], namespaces: ["nexus-relay"] } }] },
    },
  });
  const result = simulate({ policies: clusterPolicies, exceptions: [exception], gatekeeperExcludedNamespaces: [] }, target({ namespace: "nexus-relay" }));

  assert.deepEqual(result.applicable.map((entry) => entry.rule.name), ["require-image-tag"]);
  assert.ok(result.skipped.some((entry) => entry.reason.includes("relay-may-use-latest")));
});

test("namespace failure-action overrides", () => {
  const policy = normalizeKyvernoPolicy({
    kind: "ClusterPolicy",
    metadata: { name: "require-labels" },
    spec: {
      validationFailureAction: "Enforce",
      validationFailureActionOverrides: [{ action: "Audit", namespaces: ["dev-*"] }],
      rules: [{ name: "check", match: { any: [{ resources: { kinds: ["Pod"] } }] }, validate: { pattern: { metadata: { labels: { team: "?*" } } } } }],
    },
  });
  const context = { policies: [policy], exceptions: [], gatekeeperExcludedNamespaces: [] };

  assert.equal(simulate(context, target({ namespace: "prod" })).applicable[0]!.effect, "enforce");
  assert.equal(simulate(context, target({ namespace: "dev-alice" })).applicable[0]!.effect, "audit");
});

test("requester-dependent excludes are caveats, not exclusions", () => {
  const policy = normalizeKyvernoPolicy({
    kind: "ClusterPolicy",
    metadata: { name: "no-privileged" },
    spec: {
      rules: [
        {
          name: "check",
          match: { any: [{ resources: { kinds: ["Pod"] } }] },
          exclude: { any: [{ clusterRoles: ["cluster-admin"] }] },
          validate: { failureAction: "Enforce", pattern: { spec: { containers: [{ "=(securityContext)": { "=(privileged)": "false" } }] } } },
        },
      ],
    },
  });
  const result = simulate({ policies: [policy], exceptions: [], gatekeeperExcludedNamespaces: [] }, target({}));

  assert.equal(result.applicable.length, 1);
  assert.ok(result.applicable[0]!.caveats.some((caveat) => caveat.includes("cluster role cluster-admin")));
});

test("Kyverno CEL ValidatingPolicy", () => {
  const policy = normalizeKyvernoCelPolicy({
    kind: "ValidatingPolicy",
    metadata: { name: "replicas" },
    spec: {
      validationActions: ["Deny"],
      matchConstraints: {
        resourceRules: [{ apiGroups: ["apps"], apiVersions: ["v1"], operations: ["CREATE", "UPDATE"], resources: ["deployments"] }],
        namespaceSelector: { matchLabels: { env: "prod" } },
      },
      validations: [{ expression: "object.spec.replicas >= 2", message: "Production needs two replicas" }],
    },
  });
  const context = { policies: [policy], exceptions: [], gatekeeperExcludedNamespaces: [] };
  const deployment = { kind: "Deployment", group: "apps", resource: "deployments" };

  assert.equal(simulate(context, target({ ...deployment, namespaceLabels: { env: "prod" } })).byEffect.enforce.length, 1);
  assert.equal(simulate(context, target({ ...deployment, namespaceLabels: { env: "dev" } })).applicable.length, 0);
  assert.equal(simulate(context, target({ ...deployment, operation: "DELETE", namespaceLabels: { env: "prod" } })).applicable.length, 0);
});

test("policy reports", () => {
  const reports = load("policyreports.wgpolicyk8s.io");
  const entries = reports.flatMap(resultsOfReport);
  const failures = entries.filter((entry) => entry.result === "fail");

  assert.ok(entries.length > 100);
  assert.ok(failures.length >= 3, `${failures.length} failures`);
  assert.ok(failures.every((entry) => entry.policy === "disallow-latest-tag" && entry.rule?.endsWith("validate-image-tag")));
  assert.ok(failures.some((entry) => entry.resource.kind === "Pod" && entry.resource.namespace === "nexus-relay"));
  assert.equal(tally(failures).fail, failures.length);
});

// ---------------------------------------------------------------------------------------------
// Gatekeeper, synthetic
// ---------------------------------------------------------------------------------------------

test("Gatekeeper constraint", () => {
  const template = summarizeTemplate({
    metadata: { name: "k8srequiredlabels", annotations: { description: "Requires resources to carry the given labels." } },
    spec: {
      crd: { spec: { names: { kind: "K8sRequiredLabels" } } },
      targets: [{ target: "admission.k8s.gatekeeper.sh", rego: "package k8srequiredlabels\nviolation[{\"msg\": msg}] { true }" }],
    },
  })!;
  const constraint = normalizeConstraint(
    {
      kind: "K8sRequiredLabels",
      metadata: { name: "ns-must-have-owner" },
      spec: {
        enforcementAction: "dryrun",
        match: { kinds: [{ apiGroups: [""], kinds: ["Namespace", "Pod"] }], excludedNamespaces: ["kube-*"] },
        parameters: { labels: ["owner"] },
      },
      status: { totalViolations: 4 },
    },
    template,
  );
  const context = { policies: [constraint], exceptions: [], gatekeeperExcludedNamespaces: ["gatekeeper-system"] };

  assert.equal(constraint.reportedViolations, 4);
  assert.equal(simulate(context, target({})).byEffect.audit.length, 1);
  assert.equal(simulate(context, target({ namespace: "kube-system" })).applicable.length, 0);
  assert.equal(simulate(context, target({ namespace: "gatekeeper-system" })).applicable.length, 0);
  assert.equal(simulate(context, target({ kind: "Namespace", namespace: undefined, resource: "namespaces" })).applicable.length, 1);
  assert.equal(simulate(context, target({ kind: "Deployment", group: "apps", resource: "deployments" })).applicable.length, 0);
  assert.ok(constraint.rules[0]!.requirements.some((requirement) => requirement.codeLanguage === "rego"));
});

test("check: values, wildcards, operators and quantities", () => {
  assert.equal(parseQuantity("500m"), 0.5);
  assert.equal(parseQuantity("2Gi"), 2 * 2 ** 30);
  assert.equal(parseDuration("1h30m"), 5400);
  assert.ok(stringPatternMatches("nginx:1.25", "*:*"));
  assert.ok(!stringPatternMatches("nginx", "*:*"));
  assert.ok(!stringPatternMatches("nginx:latest", "!*:latest"));
  assert.ok(stringPatternMatches("256Mi", "<=1Gi"));
  assert.ok(!stringPatternMatches("2Gi", "<=1Gi"));
  assert.ok(stringPatternMatches(3, "1-5"));
  assert.ok(stringPatternMatches(7, "1!-5"));
  assert.ok(stringPatternMatches("Always", "IfNotPresent|Always"));
  assert.ok(stringPatternMatches("", "!*:latest"), "an absent image is not a latest one");
});

test("check: anchors in patterns", () => {
  const rule = (pattern: unknown) => ({ name: "r", validate: { message: "nope", pattern } });
  const pod = (containers: unknown[], extra: Record<string, unknown> = {}) => ({ kind: "Pod", metadata: { name: "p", namespace: "default", labels: { app: "web" } }, spec: { containers, ...extra } });

  // Required fields, and a missing one.
  assert.equal(checkKyvernoRule(rule({ metadata: { labels: { app: "?*" } } }), pod([])).status, "pass");
  assert.equal(checkKyvernoRule(rule({ metadata: { labels: { team: "?*" } } }), pod([])).status, "fail");

  // Conditional: only containers named nginx need a pinned tag; a run with none of them is skipped.
  const conditional = rule({ spec: { containers: [{ "(name)": "nginx", image: "!*:latest" }] } });
  assert.equal(checkKyvernoRule(conditional, pod([{ name: "nginx", image: "nginx:latest" }, { name: "side", image: "x:latest" }])).status, "fail");
  assert.equal(checkKyvernoRule(conditional, pod([{ name: "side", image: "x:latest" }])).status, "skip");

  // Equality: if set, must match; negation: must not be set; existence: at least one element.
  const equality = rule({ spec: { "=(hostNetwork)": false } });
  assert.equal(checkKyvernoRule(equality, pod([])).status, "pass");
  assert.equal(checkKyvernoRule(equality, pod([], { hostNetwork: true })).status, "fail");
  assert.equal(checkKyvernoRule(rule({ spec: { "X(hostPID)": "null" } }), pod([], { hostPID: true })).status, "fail");
  const existence = rule({ spec: { "<(containers)": [{ image: "registry.local/*" }] } });
  assert.equal(checkKyvernoRule(existence, pod([{ image: "docker.io/a" }, { image: "registry.local/b" }])).status, "pass");
  assert.equal(checkKyvernoRule(existence, pod([{ image: "docker.io/a" }])).status, "fail");

  // Global anchor: a pod without the label is not this rule's business.
  const global = rule({ metadata: { labels: { "^(tier)": "db" } }, spec: { containers: [{ image: "postgres:*" }] } });
  assert.equal(checkKyvernoRule(global, pod([{ image: "mysql:8" }])).status, "skip");

  // Resource limits by quantity, failing with the path that broke.
  const limits = rule({ spec: { containers: [{ resources: { limits: { memory: "<=1Gi" } } }] } });
  const failed = checkKyvernoRule(limits, pod([{ resources: { limits: { memory: "4Gi" } } }]));
  assert.equal(failed.status, "fail");
  assert.match(failed.detail, /spec\.containers\[0\]\.resources\.limits\.memory/);

  // anyPattern: one of them is enough.
  const any = { name: "r", validate: { anyPattern: [{ spec: { "=(hostNetwork)": false } }, { metadata: { labels: { app: "web" } } }] } };
  assert.equal(checkKyvernoRule(any, pod([], { hostNetwork: true })).status, "pass");
});

test("check: deny and preconditions over the request", () => {
  const noDeletes = {
    name: "block-deletes",
    match: { any: [{ resources: { kinds: ["ConfigMap"] } }] },
    validate: { message: "{{request.object.metadata.name}} is protected", deny: { conditions: { any: [{ key: "{{request.operation}}", operator: "Equals", value: "DELETE" }] } } },
  };
  const configMap = { kind: "ConfigMap", metadata: { name: "settings", namespace: "default" } };

  assert.equal(checkKyvernoRule(noDeletes, configMap, "CREATE").status, "pass");
  const denied = checkKyvernoRule(noDeletes, configMap, "DELETE");
  assert.equal(denied.status, "fail");
  assert.match(denied.detail, /settings is protected/);

  const labelled = {
    name: "team-label",
    preconditions: { all: [{ key: "{{ request.object.metadata.labels.\"app.kubernetes.io/part-of\" || '' }}", operator: "Equals", value: "shop" }] },
    validate: { pattern: { metadata: { labels: { team: "?*" } } } },
  };
  assert.equal(checkKyvernoRule(labelled, configMap).status, "skip");
  assert.equal(checkKyvernoRule(labelled, { ...configMap, metadata: { ...configMap.metadata, labels: { "app.kubernetes.io/part-of": "shop" } } }).status, "fail");

  const external = { name: "x", validate: { deny: { conditions: { any: [{ key: "{{ images.containers.*.registry }}", operator: "AnyNotIn", value: ["ghcr.io"] }] } } } };
  assert.equal(checkKyvernoRule(external, configMap).status, "unknown");
});

test("autogen: a draft gets the rules Kyverno 1.19 wrote for the same policy", () => {
  const live = clusterPolicies.find((policy) => policy.ref.name === "disallow-latest-tag")!;
  const raw = live.raw as any;
  const draft = withAutogenRules({ kind: "ClusterPolicy", apiVersion: "kyverno.io/v1", metadata: { name: raw.metadata.name, annotations: raw.metadata.annotations }, spec: raw.spec });
  const summary = (rules: any[]) => rules.map((rule) => ({ name: rule.name, kinds: rule.match.any[0].resources.kinds, pattern: rule.validate.pattern }));

  assert.deepEqual(summary(draft.status.autogen.rules), summary(raw.status.autogen.rules));

  // And the draft then checks a Deployment's pod template.
  const policy = normalizeKyvernoPolicy({ kind: "ClusterPolicy", ...draft });
  const deployment = (image: string) => ({
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name: "web", namespace: "shop" },
    spec: { template: { metadata: { labels: { app: "web" } }, spec: { containers: [{ name: "web", image }] } } },
  });
  const target: SimulationTarget = { kind: "Deployment", group: "apps", resource: "deployments", namespace: "shop", namespaceLabels: {}, labels: {}, operation: "CREATE" };
  const applicable = simulate({ policies: [policy], exceptions: [], gatekeeperExcludedNamespaces: [] }, target).applicable;
  const verdicts = (image: string) => Object.fromEntries(applicable.map((entry) => [entry.rule.name, entry.rule.check!(deployment(image), "CREATE").status]));

  assert.deepEqual(verdicts("nginx:latest"), { "autogen-require-image-tag": "pass", "autogen-validate-image-tag": "fail" });
  assert.deepEqual(verdicts("nginx"), { "autogen-require-image-tag": "fail", "autogen-validate-image-tag": "pass" });
  assert.deepEqual(verdicts("nginx:1.27"), { "autogen-require-image-tag": "pass", "autogen-validate-image-tag": "pass" });
});

// ---------------------------------------------------------------------------------------------
// Network, against minikube
// ---------------------------------------------------------------------------------------------

const pods = load("pods").map(toPodInfo);
const namespaces = load("namespaces");
const podNamed = (namespace: string, prefix: string) => {
  const pod = pods.find((candidate) => candidate.namespace === namespace && candidate.name.startsWith(prefix));

  assert.ok(pod, `no pod ${namespace}/${prefix}*`);

  return pod;
};
const ep = (pod: PodInfo): Endpoint => ({ type: "pod", pod });
const tcp = (port: number) => ({ port, protocol: "TCP" as const });

const minikube = buildNetworkModel(detectCni(pods, { cilium: false, calico: false }).mode, {
  kubernetesPolicies: load("networkpolicies"),
  ciliumPolicies: [],
  calicoPolicies: [],
  calicoTiers: [],
  namespaces,
});

test("CNI detection on minikube", () => {
  const detection = detectCni(pods, { cilium: false, calico: false });

  assert.equal(detection.mode, "kubernetes");
  assert.ok(detection.notes.length > 0);
});

test("argocd dex: only argocd-server on 5556, anyone on 5558", () => {
  const dex = podNamed("argocd", "argocd-dex-server");
  const server = podNamed("argocd", "argocd-server");
  const podinfo = podNamed("default", "podinfo");

  const fromServer = evaluateFlow(minikube, ep(server), ep(dex), tcp(5556));

  assert.equal(fromServer.allowed, true);
  assert.equal(fromServer.ingress?.reason, "allowed-by-rule");
  assert.equal(fromServer.egress?.reason, "not-isolated");

  const fromPodinfo = evaluateFlow(minikube, ep(podinfo), ep(dex), tcp(5556));

  assert.equal(fromPodinfo.allowed, false);
  assert.equal(fromPodinfo.ingress?.reason, "no-rule-allows");
  assert.equal(evaluateFlow(minikube, ep(podinfo), ep(dex), tcp(5558)).allowed, true);
});

test("flux: same-namespace ingress, scraping from anywhere, egress open", () => {
  const source = podNamed("flux-system", "source-controller");
  const kustomize = podNamed("flux-system", "kustomize-controller");
  const podinfo = podNamed("default", "podinfo");
  const redis = podNamed("argocd", "argocd-redis");

  assert.equal(evaluateFlow(minikube, ep(podinfo), ep(source), tcp(9090)).allowed, false);
  assert.equal(evaluateFlow(minikube, ep(podinfo), ep(source), tcp(8080)).allowed, true);
  assert.equal(evaluateFlow(minikube, ep(kustomize), ep(source), tcp(9090)).allowed, true);

  const toRedis = evaluateFlow(minikube, ep(source), ep(redis), tcp(6379));

  assert.equal(toRedis.egress?.allowed, true);
  assert.equal(toRedis.ingress?.allowed, false);
  assert.equal(toRedis.allowed, false);
  assert.equal(evaluateFlow(minikube, ep(podNamed("argocd", "argocd-repo-server")), ep(redis), tcp(6379)).allowed, true);
});

test("flux external ingress is blocked; external egress is open", () => {
  const source = podNamed("flux-system", "source-controller");

  assert.equal(evaluateFlow(minikube, { type: "external", ip: "203.0.113.7" }, ep(source), tcp(9090)).allowed, false);
  assert.equal(evaluateFlow(minikube, ep(source), { type: "external", ip: "140.82.112.3" }, tcp(443)).allowed, true);
});

test("services resolve to backends and target ports", () => {
  const services = load("services").map(toServiceInfo);
  const dexService = services.find((service) => service.namespace === "argocd" && service.name === "argocd-dex-server")!;
  const grpc = dexService.ports.find((port) => port.port === 5557)!;
  const verdict = evaluateServiceFlow(minikube, ep(podNamed("argocd", "argocd-server")), dexService, grpc, pods);

  assert.equal(verdict.backends.length, 1);
  assert.equal(verdict.allAllowed, true);
  assert.equal(evaluateServiceFlow(minikube, ep(podNamed("default", "podinfo")), dexService, grpc, pods).anyAllowed, false);
});

// ---------------------------------------------------------------------------------------------
// Cilium and Calico, synthetic
// ---------------------------------------------------------------------------------------------

const syntheticPod = (namespace: string, name: string, labels: Record<string, string>, ip: string, ports: [string, number][] = []): PodInfo =>
  toPodInfo({
    metadata: { uid: `${namespace}/${name}`, namespace, name, labels },
    spec: { containers: [{ name: "main", ports: ports.map(([portName, containerPort]) => ({ name: portName, containerPort })) }] },
    status: { phase: "Running", podIP: ip },
  });

const shopApi = syntheticPod("shop", "api", { app: "api" }, "10.0.0.10", [["http", 8080]]);
const shopLegacy = syntheticPod("shop", "legacy", { app: "api", role: "legacy" }, "10.0.0.11");
const shopDb = syntheticPod("shop", "db", { app: "db" }, "10.0.0.20", [["postgres", 5432]]);
const otherApi = syntheticPod("other", "api", { app: "api" }, "10.0.1.10");
const untrusted = syntheticPod("untrusted", "box", { app: "box" }, "10.0.2.10");
const syntheticNamespaces = ["shop", "other", "untrusted"].map((name) => ({ metadata: { name, labels: { team: name } } }));

const cilium = (policies: any[]): NetworkModel =>
  buildNetworkModel("cilium", { kubernetesPolicies: [], ciliumPolicies: policies, calicoPolicies: [], calicoTiers: [], namespaces: syntheticNamespaces });

test("Cilium: namespaced fromEndpoints, ports, and deny precedence", () => {
  const model = cilium([
    {
      kind: "CiliumNetworkPolicy",
      metadata: { name: "db-from-api", namespace: "shop" },
      spec: {
        endpointSelector: { matchLabels: { app: "db" } },
        ingress: [{ fromEndpoints: [{ matchLabels: { "k8s:app": "api" } }], toPorts: [{ ports: [{ port: "postgres", protocol: "TCP" }] }] }],
        ingressDeny: [{ fromEndpoints: [{ matchLabels: { role: "legacy" } }] }],
      },
    },
  ]);

  assert.equal(evaluateFlow(model, ep(shopApi), ep(shopDb), tcp(5432)).allowed, true);
  assert.equal(evaluateFlow(model, ep(shopApi), ep(shopDb), tcp(5433)).allowed, false);
  assert.equal(evaluateFlow(model, ep(otherApi), ep(shopDb), tcp(5432)).allowed, false, "namespaced CNP peers default to the policy's namespace");

  const legacy = evaluateFlow(model, ep(shopLegacy), ep(shopDb), tcp(5432));

  assert.equal(legacy.allowed, false);
  assert.equal(legacy.ingress?.reason, "denied-by-rule");
});

test("Cilium: cross-namespace by namespace label, entities, CIDR, empty rule", () => {
  const model = cilium([
    {
      kind: "CiliumNetworkPolicy",
      metadata: { name: "db-from-other", namespace: "shop" },
      spec: {
        endpointSelector: { matchLabels: { app: "db" } },
        ingress: [{ fromEndpoints: [{ matchLabels: { "k8s:io.kubernetes.pod.namespace": "other" } }] }],
      },
    },
    {
      kind: "CiliumClusterwideNetworkPolicy",
      metadata: { name: "api-egress" },
      spec: {
        endpointSelector: { matchLabels: { app: "api" } },
        egress: [{ toEntities: ["world"], toPorts: [{ ports: [{ port: "443" }] }] }, { toCIDR: ["192.0.2.0/24"] }],
      },
    },
    { kind: "CiliumNetworkPolicy", metadata: { name: "deny-all", namespace: "untrusted" }, spec: { endpointSelector: {}, ingress: [{}] } },
  ]);

  assert.equal(evaluateFlow(model, ep(otherApi), ep(shopDb), tcp(5432)).ingress?.allowed, true);
  assert.equal(evaluateFlow(model, ep(otherApi), ep(shopDb), tcp(5432)).egress?.allowed, false, "api egress is isolated and nothing allows the db");
  assert.equal(evaluateFlow(model, ep(shopApi), { type: "external", ip: "1.1.1.1" }, tcp(443)).allowed, true);
  assert.equal(evaluateFlow(model, ep(shopApi), { type: "external", ip: "1.1.1.1" }, tcp(80)).allowed, false);
  assert.equal(evaluateFlow(model, ep(shopApi), { type: "external", ip: "192.0.2.5" }, tcp(80)).allowed, true);
  assert.equal(evaluateFlow(model, ep(shopDb), ep(untrusted), tcp(80)).allowed, false, "ingress: [{}] denies everything");
});

test("Cilium: toPorts-only rules allow every peer; enableDefaultDeny off does not isolate", () => {
  const model = cilium([
    {
      kind: "CiliumNetworkPolicy",
      metadata: { name: "web", namespace: "shop" },
      spec: { endpointSelector: { matchLabels: { app: "api" } }, ingress: [{ toPorts: [{ ports: [{ port: "8080", protocol: "TCP" }] }] }] },
    },
    {
      kind: "CiliumNetworkPolicy",
      metadata: { name: "soft", namespace: "shop" },
      spec: { endpointSelector: { matchLabels: { app: "db" } }, enableDefaultDeny: { ingress: false }, ingress: [{ fromEndpoints: [{ matchLabels: { app: "nothing" } }] }] },
    },
  ]);

  assert.equal(evaluateFlow(model, ep(untrusted), ep(shopApi), tcp(8080)).allowed, true);
  assert.equal(evaluateFlow(model, ep(untrusted), ep(shopApi), tcp(9090)).allowed, false);
  assert.equal(evaluateFlow(model, ep(untrusted), ep(shopDb), tcp(5432)).allowed, true);
});

const calico = (calicoPolicies: any[], kubernetesPolicies: any[] = [], calicoTiers: any[] = []): NetworkModel =>
  buildNetworkModel("calico", { kubernetesPolicies, ciliumPolicies: [], calicoPolicies, calicoTiers, namespaces: syntheticNamespaces });

const allowAllIntoShop = {
  metadata: { name: "allow-all", namespace: "shop" },
  spec: { podSelector: {}, ingress: [{ from: [{ namespaceSelector: {} }] }] },
};

test("Calico: an earlier deny beats a Kubernetes allow", () => {
  const model = calico(
    [
      {
        kind: "GlobalNetworkPolicy",
        metadata: { name: "block-untrusted" },
        spec: {
          order: 100,
          selector: "all()",
          types: ["Ingress"],
          ingress: [{ action: "Deny", source: { namespaceSelector: "projectcalico.org/name == 'untrusted'" } }, { action: "Pass" }],
        },
      },
    ],
    [allowAllIntoShop],
  );

  const fromUntrusted = evaluateFlow(model, ep(untrusted), ep(shopDb), tcp(5432));

  assert.equal(fromUntrusted.allowed, false);
  assert.equal(fromUntrusted.ingress?.decidedBy?.policy.ref.name, "block-untrusted");
  assert.equal(evaluateFlow(model, ep(otherApi), ep(shopDb), tcp(5432)).allowed, true);
});

test("Calico: tiers, Pass, end-of-tier deny, port ranges, selectors scoped to the namespace", () => {
  const model = calico(
    [
      {
        kind: "GlobalNetworkPolicy",
        metadata: { name: "security.pass-shop" },
        spec: { tier: "security", order: 1, selector: "projectcalico.org/namespace == 'shop'", ingress: [{ action: "Pass" }] },
      },
      {
        kind: "GlobalNetworkPolicy",
        metadata: { name: "security.lockdown" },
        spec: { tier: "security", order: 2, selector: "all()", ingress: [{ action: "Allow", protocol: "TCP", destination: { ports: ["8000:8100"] } }] },
      },
      {
        kind: "NetworkPolicy",
        metadata: { name: "default.db", namespace: "shop" },
        spec: { selector: "app == 'db'", ingress: [{ action: "Allow", protocol: "TCP", source: { selector: "app == 'api'" }, destination: { ports: [5432] } }] },
      },
    ],
    [],
    [{ metadata: { name: "security" }, spec: { order: 100 } }],
  );

  assert.equal(evaluateFlow(model, ep(shopApi), ep(shopDb), tcp(5432)).allowed, true, "passed by security, allowed in default");
  assert.equal(evaluateFlow(model, ep(otherApi), ep(shopDb), tcp(5432)).allowed, false, "selector without namespaceSelector stays in shop");
  assert.equal(evaluateFlow(model, ep(shopApi), ep(shopDb), tcp(6432)).ingress?.reason, "end-of-tier");
  assert.equal(evaluateFlow(model, ep(shopApi), ep(untrusted), tcp(8080)).allowed, true, "untrusted is not passed, port range allows");
  assert.equal(evaluateFlow(model, ep(shopApi), ep(untrusted), tcp(9000)).ingress?.reason, "end-of-tier");
});

// ---------------------------------------------------------------------------------------------

let failed = 0;

for (const result of results) {
  if (result.error) {
    failed++;
    console.log(`✗ ${result.name}\n  ${String((result.error as Error).stack ?? result.error).split("\n").join("\n  ")}`);
  } else {
    console.log(`✓ ${result.name}`);
  }
}

console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
