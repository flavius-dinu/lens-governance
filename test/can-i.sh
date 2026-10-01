#!/usr/bin/env bash
# Captures the API server's own RBAC answers as ground truth for the engine tests:
#   test/can-i.sh <kube-context> <fixtures-dir>
# Read-only: `kubectl auth can-i` only asks (a SubjectAccessReview), it changes nothing.
set -euo pipefail

context="$1"
fixtures="$2"
cases="$fixtures/can-i.cases"
: > "$cases"

# A spread of service accounts: every one of the system and add-on namespaces, plus defaults.
accounts=$(jq -r '.items[] | select(.metadata.namespace | test("^(kube-system|argocd|flux-system|kyverno|monitoring|default|lademo)$")) | "\(.metadata.namespace)/\(.metadata.name)"' "$fixtures/serviceaccounts.json")

# verb, resource[.group], scope (ns = the account's own, all, cluster, or a namespace), subresource or "-".
# kubectl reads `pods/log` as the pod named "log", so a subresource goes in --subresource.
requests=(
  "get pods ns -"            "list pods all -"          "create pods ns -"         "create pods ns exec"
  "get pods ns log"          "list secrets ns -"        "get secrets kube-system -" "list secrets all -"
  "watch configmaps ns -"    "create deployments ns -"  "patch deployments.apps kube-system -" "delete statefulsets.apps ns -"
  "list nodes cluster -"     "get nodes cluster proxy"  "list namespaces cluster -" "create serviceaccounts ns token"
  "create rolebindings.rbac.authorization.k8s.io ns -" "bind clusterroles.rbac.authorization.k8s.io cluster -"
  "escalate roles.rbac.authorization.k8s.io ns -" "update mutatingwebhookconfigurations.admissionregistration.k8s.io cluster -"
  "list customresourcedefinitions.apiextensions.k8s.io cluster -" "list leases.coordination.k8s.io ns -"
  "create events ns -"       "list helmreleases.helm.toolkit.fluxcd.io all -" "get applications.argoproj.io ns -"
  "list clusterpolicies.kyverno.io cluster -" "update certificatesigningrequests.certificates.k8s.io cluster approval"
  "update deployments.apps ns scale" "get pods ns status"
)

for account in $accounts; do
  namespace="${account%%/*}"
  for request in "${requests[@]}"; do
    read -r verb resource scope subresource <<<"$request"
    case "$scope" in
      ns) echo "$account $verb $resource $namespace $subresource" ;;
      all) echo "$account $verb $resource * $subresource" ;;
      cluster) echo "$account $verb $resource - $subresource" ;;
      *) echo "$account $verb $resource $scope $subresource" ;;
    esac >> "$cases"
  done
done

ask() {
  local account="$1" verb="$2" resource="$3" scope="$4" subresource="$5"
  local args=(auth can-i "$verb" "$resource" --context "$CONTEXT" --as "system:serviceaccount:${account%%/*}:${account#*/}")
  [ "$subresource" != "-" ] && args+=(--subresource "$subresource")
  case "$scope" in
    "*") args+=(--all-namespaces) ;;
    "-") ;;
    *) args+=(-n "$scope") ;;
  esac
  local answer
  answer=$(kubectl "${args[@]}" 2>/dev/null || true)
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$account" "$verb" "$resource" "$scope" "$subresource" "$answer"
}
export -f ask
export CONTEXT="$context"

xargs -P 12 -L 1 bash -c 'ask "$@"' _ < "$cases" > "$fixtures/can-i.tsv"

# Requests across every namespace, and cluster-scoped ones, carry no namespace for the engine.
jq -R -s '
  split("\n") | map(select(length > 0) | split("\t")) |
  map({ sa: .[0], verb: .[1], resource: .[2],
        namespace: (if .[3] == "*" or .[3] == "-" then null else .[3] end),
        subresource: (if .[4] == "-" then null else .[4] end),
        expected: (.[5] == "yes") })' "$fixtures/can-i.tsv" > "$fixtures/can-i.json"

echo "$(jq length "$fixtures/can-i.json") cases, $(jq '[.[] | select(.expected)] | length' "$fixtures/can-i.json") allowed"
