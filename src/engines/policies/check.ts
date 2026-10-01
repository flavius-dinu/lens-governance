/**
 * Kyverno validate rules checked against a manifest, without a cluster: does the resource satisfy
 * the rule's pattern, or trip its deny conditions? What only Kyverno can settle (CEL, Pod Security,
 * variables beyond the request's own fields, image signatures) is reported as not checkable.
 */

import { matchesWildcard } from "../labels";

/* eslint-disable @typescript-eslint/no-explicit-any -- patterns and resources are open-ended JSON */
type Json = any;

export type CheckStatus = "pass" | "fail" | "skip" | "unknown" | "not-a-check";

export interface RuleCheck {
  readonly status: CheckStatus;
  /** Why: the field that failed, the condition that was not met, what could not be checked. */
  readonly detail: string;
}

export interface CheckRequest {
  readonly operation: "CREATE" | "UPDATE" | "DELETE" | "CONNECT";
  readonly object: Json;
  readonly namespace?: string;
}

const asArray = <T>(value: T[] | T | undefined | null): T[] => (Array.isArray(value) ? value : value == null ? [] : [value]);

const show = (value: unknown) => (value === undefined ? "nothing" : JSON.stringify(value));

// ---------------------------------------------------------------------------------------------
// Values: quantities, durations, wildcards and operators
// ---------------------------------------------------------------------------------------------

const quantitySuffixes: Record<string, number> = {
  n: 1e-9,
  u: 1e-6,
  m: 1e-3,
  "": 1,
  k: 1e3,
  M: 1e6,
  G: 1e9,
  T: 1e12,
  P: 1e15,
  E: 1e18,
  Ki: 2 ** 10,
  Mi: 2 ** 20,
  Gi: 2 ** 30,
  Ti: 2 ** 40,
  Pi: 2 ** 50,
  Ei: 2 ** 60,
};

/** A Kubernetes quantity ("500m", "2Gi", "3") as a number. */
export const parseQuantity = (text: string): number | undefined => {
  const match = /^([+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|M|G|T|P|E)?$/.exec(text.trim());

  return match ? Number(match[1]) * quantitySuffixes[match[2] ?? ""]! : undefined;
};

const durationUnits: Record<string, number> = { ns: 1e-9, us: 1e-6, "µs": 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 };

/** A Go duration ("1h30m", "90s") in seconds. Bare numbers are quantities, not durations. */
export const parseDuration = (text: string): number | undefined => {
  const trimmed = text.trim();

  if (!/^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/.test(trimmed)) return undefined;

  let total = 0;

  for (const [, amount, unit] of trimmed.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g)) total += Number(amount) * durationUnits[unit!]!;

  return total;
};

/** Two values compared as numbers: as quantities, or else as durations. */
const numbersOf = (left: string, right: string): [number, number] | undefined => {
  const quantities = [parseQuantity(left), parseQuantity(right)];

  if (quantities[0] !== undefined && quantities[1] !== undefined) return quantities as [number, number];

  const durations = [parseDuration(left), parseDuration(right)];

  return durations[0] !== undefined && durations[1] !== undefined ? (durations as [number, number]) : undefined;
};

const textOf = (value: unknown) => (value === null || value === undefined ? "" : typeof value === "object" ? JSON.stringify(value) : String(value));

/** One pattern atom against a value: a wildcard, a comparison, or a range. */
const atomMatches = (value: unknown, atom: string): boolean => {
  const text = textOf(value);
  const trimmed = atom.trim();

  for (const operator of [">=", "<=", ">", "<"] as const) {
    if (trimmed.startsWith(operator)) {
      const numbers = numbersOf(text, trimmed.slice(operator.length));

      if (!numbers) return false;

      const [left, right] = numbers;

      return operator === ">=" ? left >= right : operator === "<=" ? left <= right : operator === ">" ? left > right : left < right;
    }
  }

  // A range "1-10", or outside one "1!-10", of quantities or durations.
  const range = /^(.+?)(!?)-(.+)$/.exec(trimmed);

  if (range && numbersOf(range[1]!, range[3]!)) {
    const bounds = numbersOf(range[1]!, range[3]!)!;
    const numeric = numbersOf(text, range[1]!);

    if (!numeric) return false;

    const inside = numeric[0] >= bounds[0] && numeric[0] <= bounds[1];

    return range[2] === "!" ? !inside : inside;
  }

  if (trimmed.startsWith("!")) return !atomMatches(value, trimmed.slice(1));

  const numbers = numbersOf(text, trimmed);

  if (numbers && typeof value === "number") return numbers[0] === numbers[1];

  return matchesWildcard(trimmed, text);
};

/** A string pattern: alternatives separated by `|`, each of them a conjunction separated by `&`. */
export const stringPatternMatches = (value: unknown, pattern: string) =>
  pattern.split("|").some((alternative) => alternative.split("&").every((atom) => atomMatches(value, atom)));

// ---------------------------------------------------------------------------------------------
// Variables: {{ request.object.… }} and its relatives
// ---------------------------------------------------------------------------------------------

class Unsupported extends Error {}

/** Path segments of a JMESPath like `request.object.metadata.labels."app.kubernetes.io/name"`. */
const segmentsOf = (path: string): string[] | undefined => {
  const segments: string[] = [];
  const pattern = /\s*(?:"((?:[^"\\]|\\.)*)"|([A-Za-z_][A-Za-z0-9_-]*))\s*(\.|$)/y;
  let index = 0;

  while (index < path.length) {
    pattern.lastIndex = index;

    const match = pattern.exec(path);

    if (!match) return undefined;

    segments.push(match[1] ?? match[2]!);
    index = pattern.lastIndex;

    if (match[3] === "") break;
  }

  return index >= path.length ? segments : undefined;
};

const walk = (root: Json, segments: readonly string[]) => segments.reduce((value, segment) => (value === null || value === undefined ? undefined : value[segment]), root);

/** The value of one expression, or Unsupported when it needs more than the request's own fields. */
const evaluateExpression = (expression: string, request: CheckRequest): unknown => {
  const alternatives = expression.split("||").map((part) => part.trim());

  for (const alternative of alternatives) {
    const literal = /^'(.*)'$/.exec(alternative) ?? /^`(.*)`$/.exec(alternative);

    if (literal) {
      try {
        return alternative.startsWith("`") ? JSON.parse(literal[1]!) : literal[1];
      } catch {
        return literal[1];
      }
    }

    const segments = segmentsOf(alternative);

    if (!segments || segments[0] !== "request") throw new Unsupported(alternative);

    const [, field, ...rest] = segments;
    let value: unknown;

    if (field === "operation") value = request.operation;
    else if (field === "namespace") value = request.namespace;
    else if (field === "object") value = walk(request.object, rest);
    else if (field === "oldObject") value = request.operation === "CREATE" ? undefined : walk(request.object, rest);
    else throw new Unsupported(alternative);

    if (rest.length > 0 && field !== "object" && field !== "oldObject") throw new Unsupported(alternative);
    if (value !== undefined && value !== null && value !== "") return value;
  }

  return alternatives.length > 1 ? "" : undefined;
};

/** Replaces the variables in a value: a whole-string variable keeps its type, others become text. */
const substitute = (value: Json, request: CheckRequest): Json => {
  if (typeof value === "string") {
    const whole = /^\s*\{\{(.+?)\}\}\s*$/.exec(value);

    if (whole) return evaluateExpression(whole[1]!, request);

    return value.replace(/\{\{(.+?)\}\}/g, (_, expression: string) => textOf(evaluateExpression(expression, request)));
  }

  if (Array.isArray(value)) return value.map((item) => substitute(item, request));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, substitute(item, request)]));

  return value;
};

const hasVariables = (value: Json) => JSON.stringify(value ?? null).includes("{{");

// ---------------------------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------------------------

type Outcome =
  | { readonly type: "pass" }
  | { readonly type: "fail"; readonly detail: string }
  /** A conditional anchor did not hold: the element, or with a global anchor the rule, does not apply. */
  | { readonly type: "skip"; readonly detail: string; readonly global: boolean };

const pass: Outcome = { type: "pass" };

type AnchorType = "condition" | "global" | "equality" | "negation" | "existence" | "add" | "none";

const anchorOf = (key: string): { type: AnchorType; key: string } => {
  const match = /^(\^|=|X|<|\+)?\((.+)\)$/.exec(key);

  if (!match) return { type: "none", key };

  const type: Record<string, AnchorType> = { "^": "global", "=": "equality", X: "negation", "<": "existence", "+": "add" };

  return { type: match[1] ? type[match[1]]! : "condition", key: match[2]! };
};

const join = (path: string, key: string) => (path ? `${path}.${key}` : key);

const isEmpty = (value: unknown) =>
  value === undefined || value === null || value === "" || value === 0 || value === false || (Array.isArray(value) && value.length === 0) || (typeof value === "object" && Object.keys(value as object).length === 0);

const matchValue = (value: Json, pattern: Json, path: string): Outcome => {
  if (pattern === null) return isEmpty(value) ? pass : { type: "fail", detail: `${path || "the resource"} must be empty, and is ${show(value)}` };
  if (Array.isArray(pattern)) return matchArray(value, pattern, path);
  if (typeof pattern === "object") return matchMap(value, pattern, path);

  if (typeof pattern === "string") {
    if (stringPatternMatches(value, pattern)) return pass;

    return { type: "fail", detail: value === undefined ? `${path} is not set, and must match "${pattern}"` : `${path} is ${show(value)}, which does not match "${pattern}"` };
  }

  // Numbers and booleans compare as equal values, a number also with a quantity written as text.
  const equal =
    value === pattern ||
    (typeof pattern === "number" && typeof value === "string" && parseQuantity(value) === pattern) ||
    (typeof pattern === "boolean" && String(value) === String(pattern));

  return equal ? pass : { type: "fail", detail: `${path} is ${show(value)}, and must be ${show(pattern)}` };
};

const matchMap = (value: Json, pattern: Record<string, Json>, path: string): Outcome => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { type: "fail", detail: `${path || "the resource"} must be a map${value === undefined ? ", and is missing" : ""}` };
  }

  const entries = Object.entries(pattern).map(([key, child]) => ({ ...anchorOf(key), child }));

  // Conditions first: when one does not hold, the rest of the map is not looked at.
  for (const entry of entries.filter((candidate) => candidate.type === "condition" || candidate.type === "global")) {
    const here = join(path, entry.key);
    const outcome = entry.key in value ? matchValue(value[entry.key], entry.child, here) : { type: "fail" as const, detail: `${here} is not set` };

    if (outcome.type === "fail") return { type: "skip", detail: outcome.detail, global: entry.type === "global" };
    if (outcome.type === "skip") return outcome;
  }

  for (const entry of entries) {
    const here = join(path, entry.key);
    const present = entry.key in value && value[entry.key] !== undefined;

    switch (entry.type) {
      case "condition":
      case "global":
      case "add":
        break;
      case "negation":
        if (present) return { type: "fail", detail: `${here} must not be set` };
        break;
      case "equality": {
        if (!present) break;

        const outcome = matchValue(value[entry.key], entry.child, here);

        if (outcome.type !== "pass") return outcome;
        break;
      }
      case "existence": {
        const list = value[entry.key];

        if (!Array.isArray(list)) return { type: "fail", detail: `${here} must be a list with at least one matching element` };

        const element = Array.isArray(entry.child) ? entry.child[0] : entry.child;

        if (!list.some((item, index) => matchValue(item, element, `${here}[${index}]`).type === "pass")) {
          return { type: "fail", detail: `no element of ${here} matches` };
        }
        break;
      }
      default: {
        if (entry.child === "*") {
          if (!present || value[entry.key] === null) return { type: "fail", detail: `${here} must be set` };
          break;
        }

        if (!present && typeof entry.child === "object" && entry.child !== null) return { type: "fail", detail: `${here} must be set` };

        const outcome = matchValue(value[entry.key], entry.child, here);

        if (outcome.type !== "pass") return outcome;
      }
    }
  }

  return pass;
};

const matchArray = (value: Json, pattern: Json[], path: string): Outcome => {
  if (!Array.isArray(value)) return { type: "fail", detail: `${path} must be a list${value === undefined ? ", and is missing" : ""}` };
  if (pattern.length === 0) return pass;

  const [first] = pattern;

  // A map pattern: every element must match the first, but an element its conditions skip is left
  // alone. Plain values compare position by position, as Kyverno does.
  if (first && typeof first === "object") {
    let skipped = 0;
    let lastSkip: Outcome | undefined;

    for (const [index, item] of value.entries()) {
      const outcome = matchValue(item, first, `${path}[${index}]`);

      if (outcome.type === "fail") return outcome;

      if (outcome.type === "skip") {
        if (outcome.global) return outcome;

        skipped++;
        lastSkip = outcome;
      }
    }

    return value.length > 0 && skipped === value.length && lastSkip ? lastSkip : pass;
  }

  for (const [index, element] of pattern.entries()) {
    if (index >= value.length) return { type: "fail", detail: `${path} has ${value.length} elements, and must have at least ${pattern.length}` };

    const outcome = matchValue(value[index], element, `${path}[${index}]`);

    if (outcome.type !== "pass") return outcome;
  }

  return pass;
};

// ---------------------------------------------------------------------------------------------
// Conditions: preconditions and deny
// ---------------------------------------------------------------------------------------------

const listOf = (value: unknown): unknown[] => (Array.isArray(value) ? value : [value]);

const anyMatches = (values: unknown[], candidates: unknown[]) => values.some((value) => candidates.some((candidate) => equalOrWildcard(value, candidate)));

const equalOrWildcard = (value: unknown, candidate: unknown) =>
  typeof candidate === "string" && typeof value === "string" ? matchesWildcard(candidate, value) : JSON.stringify(value) === JSON.stringify(candidate);

const compareNumbers = (key: unknown, value: unknown, test: (left: number, right: number) => boolean) => {
  const numbers = numbersOf(textOf(key), textOf(value));

  if (!numbers) throw new Unsupported(`compare ${show(key)} with ${show(value)}`);

  return test(numbers[0], numbers[1]);
};

const conditionHolds = (condition: Json, request: CheckRequest): boolean => {
  const key = substitute(condition.key, request);
  const value = substitute(condition.value, request);

  switch (condition.operator) {
    case "Equals":
    case "Equal":
      return equalOrWildcard(key, value);
    case "NotEquals":
    case "NotEqual":
      return !equalOrWildcard(key, value);
    case "In":
    case "AllIn":
      return listOf(key).every((item) => anyMatches([item], listOf(value)));
    case "AnyIn":
      return anyMatches(listOf(key), listOf(value));
    case "NotIn":
    case "AllNotIn":
      return listOf(key).every((item) => !anyMatches([item], listOf(value)));
    case "AnyNotIn":
      return listOf(key).some((item) => !anyMatches([item], listOf(value)));
    case "GreaterThan":
    case "DurationGreaterThan":
      return compareNumbers(key, value, (left, right) => left > right);
    case "GreaterThanOrEquals":
    case "DurationGreaterThanOrEquals":
      return compareNumbers(key, value, (left, right) => left >= right);
    case "LessThan":
    case "DurationLessThan":
      return compareNumbers(key, value, (left, right) => left < right);
    case "LessThanOrEquals":
    case "DurationLessThanOrEquals":
      return compareNumbers(key, value, (left, right) => left <= right);
    default:
      throw new Unsupported(`the operator ${condition.operator}`);
  }
};

/** `{ any, all }`, or in older policies a bare list meaning all. No conditions hold vacuously. */
const conditionsHold = (block: Json, request: CheckRequest): boolean => {
  if (!block) return true;
  if (Array.isArray(block)) return block.every((condition) => conditionHolds(condition, request));

  const any = asArray<Json>(block.any);
  const all = asArray<Json>(block.all);

  return (any.length === 0 || any.some((condition) => conditionHolds(condition, request))) && all.every((condition) => conditionHolds(condition, request));
};

// ---------------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------------

const unknown = (detail: string): RuleCheck => ({ status: "unknown", detail });

const fromOutcome = (outcome: Outcome, message: string | undefined): RuleCheck => {
  if (outcome.type === "pass") return { status: "pass", detail: "The resource matches the pattern." };
  if (outcome.type === "skip") return { status: "skip", detail: `Not applied: its condition does not hold (${outcome.detail}).` };

  return { status: "fail", detail: message ? `${message} (${outcome.detail})` : outcome.detail };
};

const checkPatterns = (validate: Json, resource: Json, request: CheckRequest, message: string | undefined): RuleCheck => {
  const patterns = validate.pattern !== undefined ? [validate.pattern] : asArray<Json>(validate.anyPattern);
  const outcomes = patterns.map((pattern) => matchValue(resource, substitute(pattern, request), ""));

  if (validate.pattern !== undefined) return fromOutcome(outcomes[0]!, message);

  if (outcomes.some((outcome) => outcome.type === "pass")) return { status: "pass", detail: "The resource matches one of the patterns." };
  if (outcomes.every((outcome) => outcome.type === "skip")) return fromOutcome(outcomes[0]!, message);

  const reasons = outcomes.map((outcome, index) => `${index + 1}: ${outcome.type === "fail" ? outcome.detail : "its condition does not hold"}`);

  return { status: "fail", detail: `${message ? `${message} ` : ""}(no pattern matches: ${reasons.join("; ")})` };
};

/**
 * Checks one Kyverno rule of a ClusterPolicy or Policy against a resource. The resource is the
 * one the rule is written for: for an autogen rule, the controller, with its pod template inside.
 */
export const checkKyvernoRule = (rule: Json, resource: Json, operation: CheckRequest["operation"] = "CREATE"): RuleCheck => {
  const request: CheckRequest = { operation, object: resource, namespace: resource?.metadata?.namespace };

  if (rule.mutate) return { status: "not-a-check", detail: "Mutates the resource: nothing is refused." };
  if (rule.generate) return { status: "not-a-check", detail: "Generates other resources: nothing is refused." };
  if (rule.verifyImages) return unknown("Image signatures and attestations are verified against the registry, which the lab does not reach.");
  if (!rule.validate) return unknown("A rule of a type the lab does not check.");

  try {
    if (rule.celPreconditions) return unknown("Its CEL preconditions are evaluated by Kyverno only.");
    if (!conditionsHold(rule.preconditions, request)) return { status: "skip", detail: "Not applied: its preconditions do not hold for this resource." };

    const validate = rule.validate;
    const message = typeof validate.message === "string" ? textOf(hasVariables(validate.message) ? safeSubstitute(validate.message, request) : validate.message) : undefined;

    if (validate.pattern !== undefined || validate.anyPattern !== undefined) return checkPatterns(validate, resource, request, message);

    if (validate.deny) {
      if (!validate.deny.conditions) return { status: "fail", detail: message ?? "Denied: the rule has no conditions, so it denies everything it matches." };

      return conditionsHold(validate.deny.conditions, request)
        ? { status: "fail", detail: message ?? "Denied: its deny conditions hold." }
        : { status: "pass", detail: "Its deny conditions do not hold." };
    }

    if (validate.podSecurity) return unknown(`Pod Security Standard "${validate.podSecurity.level ?? "baseline"}": checked by Kyverno itself.`);
    if (validate.cel) return unknown("CEL expressions are evaluated by Kyverno only.");
    if (validate.foreach) return unknown("foreach rules walk lists through JMESPath, which the lab does not evaluate.");
    if (validate.manifests) return unknown("Manifest signatures are verified by Kyverno only.");

    return unknown("A validation the lab does not check.");
  } catch (error) {
    if (error instanceof Unsupported) return unknown(`Uses ${error.message}, which only Kyverno can evaluate (context, API calls or JMESPath functions).`);

    throw error;
  }
};

const safeSubstitute = (text: string, request: CheckRequest) => {
  try {
    return substitute(text, request);
  } catch {
    return text;
  }
};
