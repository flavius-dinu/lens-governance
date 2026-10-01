/** Starting points for the lab's editors, inserted with the user's namespace of choice. */

export interface LabExample {
  readonly id: string;
  readonly label: string;
  readonly target: "drafts" | "tests";
  readonly yaml: (namespace: string) => string;
}

export const labExamples: readonly LabExample[] = [
  {
    id: "default-deny",
    label: "Default deny",
    target: "drafts",
    yaml: (namespace) => `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: ${namespace}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
`,
  },
  {
    id: "same-namespace",
    label: "Allow same namespace + DNS",
    target: "drafts",
    yaml: (namespace) => `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: ${namespace}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: {}
  egress:
    - to:
        - podSelector: {}
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
`,
  },
  {
    id: "require-labels",
    label: "Require team label",
    target: "drafts",
    yaml: () => `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-team-label
  annotations:
    policies.kyverno.io/title: Require a team label
    policies.kyverno.io/description: Every pod says which team owns it.
spec:
  rules:
    - name: check-team
      match:
        any:
          - resources:
              kinds: [Pod]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kube-public, kube-node-lease]
      validate:
        failureAction: Enforce
        message: "Pods need a team label."
        pattern:
          metadata:
            labels:
              team: "?*"
`,
  },
  {
    id: "memory-limits",
    label: "Memory limits ≤ 1Gi",
    target: "drafts",
    yaml: () => `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: limit-memory
  annotations:
    policies.kyverno.io/title: Limit container memory
spec:
  rules:
    - name: memory-limit
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        failureAction: Audit
        message: "Every container sets a memory limit of at most 1Gi."
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "<=1Gi"
`,
  },
  {
    id: "web-deployment",
    label: "Web Deployment",
    target: "tests",
    yaml: (namespace) => `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: ${namespace}
  labels:
    app: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
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
          resources:
            limits:
              memory: 256Mi
`,
  },
  {
    id: "debug-pod",
    label: "Debug pod",
    target: "tests",
    yaml: (namespace) => `apiVersion: v1
kind: Pod
metadata:
  name: debug
  namespace: ${namespace}
  labels:
    app: debug
spec:
  containers:
    - name: shell
      image: busybox
      command: [sleep, "3600"]
`,
  },
];
