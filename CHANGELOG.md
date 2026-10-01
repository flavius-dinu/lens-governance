# Changelog

What changed in each version of this extension, newest first.

## 0.1.0

- Service account permissions: effective RBAC per service account, risk flags, and who-can lookups.
- Admission policies: Kyverno and OPA Gatekeeper policies, their violations, and a simulator for which policies apply to a resource.
- Network reachability: a simulator, matrix, coverage and policy list across Kubernetes NetworkPolicy, Cilium and Calico.
- Entry points from the navigator, resource menus, details panels and the command palette.
- On a cluster whose credentials may not list roles and bindings, the permissions view says so instead of rating every account harmless.
- While loading, the views name the lists they are still waiting for.
- The reachability simulator picks pods and services from a searchable list, grouped by namespace.
- Every picker (kinds, namespaces, verbs, resources) opens a list of all its choices, narrowed as you type; before, a box already holding a value offered nothing else.
- Wider port and search boxes.
- Policy lab: draft policies and test manifests checked against the cluster, with admission verdicts per rule, network reachability for test workloads, and the drafts' effect on running pods.
- Write policies with the AI tool selected in Lens, or with Ask AI.
- Copy any resource into the policy lab from its menu.
- Permissions dashboard: accounts by risk level, each level a click away from its list.
- Reachability matrix: pick all namespaces, or all but the system ones, in one click; up to 150 workloads drawn.
