/**
 * Results of policy reports, the wgpolicyk8s.io (and openreports.io) PolicyReport and
 * ClusterPolicyReport Kyverno writes as it scans resources, read into one flat list.
 */

import type { PolicyResult } from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any -- reports are open-ended JSON */
type Json = any;

const asArray = <T>(value: T[] | T | undefined | null): T[] => (Array.isArray(value) ? value : value == null ? [] : [value]);

const results = new Set(["pass", "fail", "warn", "error", "skip"]);

const timestampOf = (value: Json): number | undefined => {
  if (typeof value?.seconds === "number") return value.seconds * 1000;
  if (typeof value === "string") return Date.parse(value) || undefined;

  return undefined;
};

/** Kyverno names a namespaced policy `namespace/name` in its results; a cluster policy by its name. */
const splitPolicy = (policy: string) => {
  const slash = policy.indexOf("/");

  return slash === -1 ? { policy } : { policyNamespace: policy.slice(0, slash), policy: policy.slice(slash + 1) };
};

export const resultsOfReport = (report: Json): PolicyResult[] =>
  asArray<Json>(report.results).flatMap((result) => {
    if (!results.has(result.result)) return [];

    const resources = asArray<Json>(result.resources);
    const subjects = resources.length > 0 ? resources : report.scope ? [report.scope] : [{ kind: "Unknown", name: "?" }];
    const { policy, policyNamespace } = splitPolicy(String(result.policy ?? ""));

    return subjects.map((subject): PolicyResult => ({
      engine: String(result.source ?? "kyverno").toLowerCase().includes("validatingpolicy") ? "kyverno-cel" : "kyverno",
      policy,
      policyNamespace,
      rule: result.rule,
      result: result.result,
      message: result.message,
      severity: result.severity,
      resource: { kind: subject.kind, apiVersion: subject.apiVersion, namespace: subject.namespace ?? report.metadata?.namespace, name: subject.name },
      timestamp: timestampOf(result.timestamp),
    }));
  });

export interface ResultTally {
  pass: number;
  fail: number;
  warn: number;
  error: number;
  skip: number;
}

export const emptyTally = (): ResultTally => ({ pass: 0, fail: 0, warn: 0, error: 0, skip: 0 });

export const tally = (entries: readonly PolicyResult[]) =>
  entries.reduce((sum, entry) => {
    sum[entry.result]++;

    return sum;
  }, emptyTally());
