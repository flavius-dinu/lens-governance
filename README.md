# Governance

See how a cluster is actually governed: what each service account may do, what admission policy requires, and which pods can reach which. The answers are worked out from the RBAC, policy and NetworkPolicy objects already in the cluster. Nothing is installed in it, and nothing in it is changed.

## Features

- **Service account permissions.** A dashboard counts the accounts at each risk level (critical, high, medium, low, none) and how many of them run pods; click a level to list its accounts. Every service account's effective permissions, resolved through its Roles, ClusterRoles and bindings, with risky grants flagged: full admin, `bind`/`escalate`, impersonation, webhook changes, reading secrets, creating tokens, exec into pods, approving CSRs, and more. Ask "who can *verb* *resource*?" and see which bindings grant it.
- **Admission policies.** Kyverno policies (ClusterPolicy, Policy, CEL ValidatingPolicy, PolicyExceptions) and OPA Gatekeeper constraints, shown with what each rule requires, its failure action, and its current violations from PolicyReports and constraint status. A simulator shows which policies would apply to a given resource, and why one is excluded.
- **Network reachability.** Kubernetes NetworkPolicy, Cilium and Calico policies evaluated together:
  - *Simulator*: can this pod, service or external IP reach that one on this port? Shows the verdict for each backend and the rule that decided it.
  - *Matrix*: reachability between the workloads of the namespaces you choose, all of them at once if you like (up to 150 workloads).
  - *Coverage*: how isolated each namespace is (ingress and egress isolation, default deny), least isolated first.
  - *Policies*: the policies themselves.

  The CNI is detected so that you can tell whether the policies are actually enforced.
- **Policy lab.** Try policies before you apply them. Paste or write draft policies (NetworkPolicy, Cilium, Calico, Kyverno, Gatekeeper) and test manifests (Pods, Deployments and other workloads, Services, Namespaces, any resource):
  - Each test manifest gets an admission verdict: rejected, admitted, warned or reported. Every rule that applies says whether the manifest complies, with the field that fails. Kyverno pattern and deny rules are checked offline, including the rules Kyverno writes out for Deployments and other controllers. CEL, Rego, Pod Security and image verification are marked as checkable only by their engine.
  - Each test workload shows which policies isolate it, how many of the cluster's workloads can reach it, and whether it can reach DNS and the outside.
  - Draft policies show their effect on the cluster as it runs now: the pods a network policy would select, and the running pods a Kyverno rule would fail.
  - The drafts are laid over the cluster's own policies in the other views too, marked "draft", until you switch them off. A draft with the same kind, namespace and name as a policy in the cluster replaces it.
  - **Write with AI.** Describe a policy and the lab asks the AI tool you selected in Lens (Claude Code, Codex, Gemini CLI and others) to write it, then shows the YAML for you to add or discard. The request, the lab's manifests, and the names and labels of the cluster's namespaces, workloads and policies are sent to that tool. **Ask AI instead** opens Lens's assistant with the same briefing.

## Usage

For each connected cluster, the navigator shows a **Governance** item with four views: *Service account permissions*, *Admission policies*, *Network reachability* and *Policy lab*. Each view opens in a tab.

You can also reach them from:

- **Resource menus.** *Inspect permissions* on a ServiceAccount, *Check network reachability* on a Pod, and *Admission policies that apply* and *Copy into the policy lab* on any resource. Copying a policy makes it a draft you can change; copying anything else makes it a test manifest.
- **Details panels.** A *Permissions* section on ServiceAccounts and a *Network policy* section on Pods.
- **Command palette.** `Governance: … of this cluster` for the active cluster.

Nothing is ever applied to the cluster: the lab only simulates. Its drafts are saved on your machine, per cluster.

The views only read what your kubeconfig user may list. A policy engine whose CRDs aren't installed is shown as not installed, and a kind you aren't allowed to list is reported with its error. The rest of the view still works.

What changed in each version is in [CHANGELOG.md](./CHANGELOG.md).
