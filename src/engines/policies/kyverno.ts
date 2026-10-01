/**
 * Kyverno policies, read into what they require and whom they apply to: the classic
 * ClusterPolicy and Policy of kyverno.io, the CEL ValidatingPolicy and its namespaced sibling of
 * policies.kyverno.io, and the PolicyExceptions that exempt resources from either.
 */

import { describeSelector, type LabelSelector, matchesSelector, matchesWildcard } from "../labels";
import { checkKyvernoRule } from "./check";
import {
  type MatchOutcome,
  type NormalizedPolicy,
  type NormalizedRule,
  type PolicyEffect,
  type PolicyRef,
  policyRefKey,
  type Requirement,
  type SimulationTarget,
} from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any -- policies are open-ended JSON, read defensively */
type Json = any;

const asArray = <T>(value: T[] | T | undefined | null): T[] => (Array.isArray(value) ? value : value == null ? [] : [value]);

const code = (value: unknown) => (typeof value === "string" ? value : JSON.stringify(value));

// ---------------------------------------------------------------------------------------------
// Patterns, in words
// ---------------------------------------------------------------------------------------------

const looksNumeric = (text: string) => /^-?\d+(\.\d+)?([a-zA-Z]{0,3})$/.test(text.trim());

const describeAtom = (raw: string): string => {
  const atom = raw.trim();

  if (atom === "*") return "set to any value";
  if (atom === "?*") return "set to a non-empty value";
  if (atom === "") return "empty";

  for (const [operator, words] of [
    [">=", "at least"],
    ["<=", "at most"],
    [">", "greater than"],
    ["<", "less than"],
  ] as const) {
    if (atom.startsWith(operator)) return `${words} ${atom.slice(operator.length).trim()}`;
  }

  if (atom.startsWith("!")) {
    const rest = atom.slice(1);

    return rest.includes("*") || rest.includes("?") ? `not matching \`${rest}\`` : `anything but \`${rest}\``;
  }

  const outside = /^(.+)!-(.+)$/.exec(atom);

  if (outside && looksNumeric(outside[1]!) && looksNumeric(outside[2]!)) return `outside ${outside[1]}–${outside[2]}`;

  const range = /^(-?[\d.]+[a-zA-Z]*)-(-?[\d.]+[a-zA-Z]*)$/.exec(atom);

  if (range) return `between ${range[1]} and ${range[2]}`;

  if (atom.includes("*") || atom.includes("?")) return `matching \`${atom}\``;

  return `\`${atom}\``;
};

/** `"!*:latest"` → "not matching `*:latest`"; `"a | b"` → "`a` or `b`". */
export const describePatternValue = (value: unknown): string => {
  if (value === null) return "unset";
  if (typeof value === "boolean" || typeof value === "number") return `\`${value}\``;
  if (typeof value !== "string") return `\`${code(value)}\``;

  return value
    .split("|")
    .map((alternative) =>
      alternative
        .split("&")
        .map(describeAtom)
        .join(" and "),
    )
    .join(" or ");
};

type AnchorType = "conditional" | "equality" | "existence" | "negation" | "global" | "add" | "none";

const parseAnchor = (key: string): { type: AnchorType; key: string } => {
  const match = /^([=^X+<]?)\((.+)\)$/.exec(key);

  if (!match) return { type: "none", key };

  const type = ({ "": "conditional", "=": "equality", "^": "existence", X: "negation", "+": "add", "<": "global" } as const)[
    match[1] as "" | "=" | "^" | "X" | "+" | "<"
  ];

  return { type, key: match[2]! };
};

const joinPath = (path: string, key: string) => (path ? `${path}.${key}` : key);

const isLeaf = (value: unknown) => value === null || typeof value !== "object";

/**
 * Lines that say, in words, what a validate pattern requires. Conditions (anchors that gate the
 * rest) come first, so that a reader sees "Only when … : … must …".
 */
export const describePattern = (pattern: Json, mode: "validate" | "mutate" = "validate"): string[] => {
  const conditions: string[] = [];
  const lines: string[] = [];

  const walk = (node: Json, path: string, qualifier: string) => {
    if (Array.isArray(node)) {
      node.forEach((element) => walk(element, `${path}[*]`, qualifier));

      return;
    }

    if (isLeaf(node)) {
      if (mode === "mutate") lines.push(`${qualifier}Sets \`${path}\` to \`${code(node)}\``);
      else lines.push(`${qualifier}\`${path}\` must be ${describePatternValue(node)}`);

      return;
    }

    for (const [rawKey, child] of Object.entries(node as Record<string, Json>)) {
      const anchor = parseAnchor(rawKey);
      const childPath = joinPath(path, anchor.key);

      switch (anchor.type) {
        case "conditional":
          if (isLeaf(child)) conditions.push(`\`${childPath}\` is ${describePatternValue(child)}`);
          else walk(child, childPath, qualifier);
          break;

        case "global":
          if (isLeaf(child)) conditions.push(`\`${childPath}\` is ${describePatternValue(child)} (otherwise the rule is skipped)`);
          else walk(child, childPath, qualifier);
          break;

        case "equality":
          if (isLeaf(child)) lines.push(`${qualifier}If \`${childPath}\` is set, it must be ${describePatternValue(child)}`);
          else walk(child, childPath, `${qualifier}If \`${childPath}\` is set: `);
          break;

        case "existence":
          walk(child, childPath, `${qualifier}At least one entry of \`${childPath}\`: `);
          break;

        case "negation":
          lines.push(`${qualifier}\`${childPath}\` must not be set`);
          break;

        case "add":
          if (isLeaf(child)) lines.push(`${qualifier}Adds \`${childPath}\` = \`${code(child)}\` when it is missing`);
          else walk(child, childPath, `${qualifier}When \`${childPath}\` is missing, adds: `);
          break;

        default:
          walk(child, childPath, qualifier);
      }
    }
  };

  walk(pattern, "", "");

  return conditions.length > 0 ? [`Only when ${conditions.join(" and ")}:`, ...lines.map((line) => `  ${line}`)] : lines;
};

const operatorWords: Record<string, string> = {
  Equals: "equals",
  NotEquals: "does not equal",
  Equal: "equals",
  NotEqual: "does not equal",
  In: "is in",
  NotIn: "is not in",
  AnyIn: "has any value in",
  AllIn: "has all values in",
  AnyNotIn: "has some value not in",
  AllNotIn: "has no value in",
  GreaterThan: "is greater than",
  GreaterThanOrEquals: "is at least",
  LessThan: "is less than",
  LessThanOrEquals: "is at most",
  DurationGreaterThan: "is a longer duration than",
  DurationGreaterThanOrEquals: "is at least the duration",
  DurationLessThan: "is a shorter duration than",
  DurationLessThanOrEquals: "is at most the duration",
};

const describeCondition = (condition: Json) =>
  `${code(condition.key)} ${operatorWords[condition.operator] ?? condition.operator} ${code(condition.value)}`;

/** Kyverno conditions come as `{ any, all }` or, in older policies, as a bare list meaning all. */
const describeConditionBlock = (block: Json, lead: string): Requirement[] => {
  if (!block) return [];

  const groups: { label: string; items: Json[] }[] = Array.isArray(block)
    ? [{ label: "all", items: block }]
    : [
        { label: "any", items: asArray(block.any) },
        { label: "all", items: asArray(block.all) },
      ];

  return groups
    .filter((group) => group.items.length > 0)
    .map((group) => ({
      text: `${lead} ${group.items.length > 1 ? `${group.label} of these hold` : "this holds"}:`,
      code: group.items.map(describeCondition).join(group.label === "any" ? "\n  OR " : "\n  AND "),
      codeLanguage: "jmespath" as const,
    }));
};

// ---------------------------------------------------------------------------------------------
// Rule bodies, in words
// ---------------------------------------------------------------------------------------------

const describeValidate = (validate: Json): Requirement[] => {
  const requirements: Requirement[] = [];

  if (validate.pattern) requirements.push(...describePattern(validate.pattern).map((text) => ({ text })));

  if (validate.anyPattern) {
    const patterns = asArray(validate.anyPattern);

    requirements.push({ text: `Must match at least one of ${patterns.length} patterns:` });
    patterns.forEach((pattern, index) =>
      requirements.push(...describePattern(pattern).map((text) => ({ text: `  ${index + 1}. ${text}` }))),
    );
  }

  if (validate.deny) {
    const denied = describeConditionBlock(validate.deny.conditions, "Rejected when");

    requirements.push(...(denied.length > 0 ? denied : [{ text: "Always rejected (deny without conditions)" }]));
  }

  if (validate.podSecurity) {
    const { level, version, exclude } = validate.podSecurity;

    requirements.push({ text: `Must meet the Pod Security Standard "${level ?? "baseline"}" (version ${version ?? "latest"})` });

    for (const exclusion of asArray<Json>(exclude)) {
      requirements.push({
        text: `  except control "${exclusion.controlName}"${exclusion.images ? ` for images ${asArray(exclusion.images).join(", ")}` : ""}${
          exclusion.restrictedField ? ` on ${exclusion.restrictedField}` : ""
        }${exclusion.values ? ` allowing ${asArray(exclusion.values).join(", ")}` : ""}`,
      });
    }
  }

  if (validate.cel) {
    for (const expression of asArray<Json>(validate.cel.expressions)) {
      requirements.push({ text: expression.message ?? "Must satisfy", code: expression.expression, codeLanguage: "cel" });
    }
  }

  if (validate.foreach) {
    for (const each of asArray<Json>(validate.foreach)) {
      requirements.push({ text: `For each element of ${code(each.list)}:` });

      if (each.pattern) requirements.push(...describePattern(each.pattern).map((text) => ({ text: `  ${text}` })));
      if (each.anyPattern) requirements.push({ text: `  must match one of ${asArray(each.anyPattern).length} patterns` });
      if (each.deny) requirements.push(...describeConditionBlock(each.deny.conditions, "  Rejected when"));
    }
  }

  if (validate.manifests) requirements.push({ text: "Requires the manifest itself to be signed" });

  if (requirements.length === 0) requirements.push({ text: "Validates", code: code(validate), codeLanguage: "json" });

  return requirements;
};

const describeMutate = (mutate: Json): Requirement[] => {
  const requirements: Requirement[] = [];

  if (mutate.patchStrategicMerge) requirements.push(...describePattern(mutate.patchStrategicMerge, "mutate").map((text) => ({ text })));

  if (mutate.patchesJson6902) {
    requirements.push({ text: "Applies a JSON patch", code: code(mutate.patchesJson6902), codeLanguage: "yaml" });
  }

  for (const each of asArray<Json>(mutate.foreach)) {
    requirements.push({ text: `For each element of ${code(each.list)}:` });

    if (each.patchStrategicMerge) {
      requirements.push(...describePattern(each.patchStrategicMerge, "mutate").map((text) => ({ text: `  ${text}` })));
    }

    if (each.patchesJson6902) requirements.push({ text: "  Applies a JSON patch", code: code(each.patchesJson6902), codeLanguage: "yaml" });
  }

  if (mutate.targets) {
    const targets = asArray<Json>(mutate.targets).map((target) => `${target.kind} ${target.namespace ? `${target.namespace}/` : ""}${target.name ?? "*"}`);

    requirements.push({ text: `Mutates existing resources: ${targets.join(", ")}` });
  }

  if (requirements.length === 0) requirements.push({ text: "Mutates", code: code(mutate), codeLanguage: "json" });

  return requirements;
};

const describeGenerate = (generate: Json): Requirement[] => {
  const source = generate.clone ? ` cloned from ${generate.clone.namespace}/${generate.clone.name}` : generate.cloneList ? " cloned from a list" : "";
  const what = generate.kind ? `${generate.kind} ${generate.namespace ? `${generate.namespace}/` : ""}${generate.name ?? ""}` : "resources";

  return [
    { text: `Creates ${what}${source}${generate.synchronize ? ", kept in sync" : ""}` },
    ...(generate.data ? [{ text: "With content", code: code(generate.data), codeLanguage: "json" as const }] : []),
  ];
};

const describeVerifyImages = (verify: Json): Requirement[] => {
  const references = asArray(verify.imageReferences ?? verify.image).join(", ") || "*";
  const requirements: Requirement[] = [{ text: `Images matching ${references} must be verified` }];

  for (const attestorSet of asArray<Json>(verify.attestors)) {
    for (const entry of asArray<Json>(attestorSet.entries)) {
      if (entry.keys) requirements.push({ text: "  signed with a given public key" });
      if (entry.keyless) {
        requirements.push({
          text: `  signed keyless by ${entry.keyless.subject ?? "any subject"}${entry.keyless.issuer ? ` from ${entry.keyless.issuer}` : ""}`,
        });
      }
      if (entry.certificates) requirements.push({ text: "  signed with a given certificate" });
    }
  }

  for (const attestation of asArray<Json>(verify.attestations)) {
    requirements.push({ text: `  with an attestation of type ${attestation.type ?? attestation.predicateType}` });
  }

  if (verify.mutateDigest) requirements.push({ text: "Rewrites image tags to digests" });
  if (verify.verifyDigest) requirements.push({ text: "Requires images to be referenced by digest" });

  return requirements;
};

// ---------------------------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------------------------

interface KindSpec {
  readonly group?: string;
  readonly kind: string;
  readonly subresource?: string;
}

/** `Pod`, `v1/Pod`, `apps/v1/Deployment`, `Pod/exec`, `apps/*\/Deployment`. */
const parseKindSpec = (spec: string): KindSpec => {
  const parts = spec.split("/");

  if (parts.length === 1) return { kind: parts[0]! };

  if (parts.length === 2) {
    return /^[A-Z*]/.test(parts[0]!) ? { kind: parts[0]!, subresource: parts[1] } : { group: "", kind: parts[1]! };
  }

  return { group: parts[0]!, kind: parts[2]!, subresource: parts[3] };
};

const kindSpecMatches = (spec: KindSpec, target: SimulationTarget) =>
  !spec.subresource && matchesWildcard(spec.kind, target.kind) && (spec.group === undefined || spec.group === "*" || spec.group === target.group);

interface FilterVerdict {
  readonly matches: boolean;
  readonly reasons: string[];
  readonly caveats: string[];
  readonly failure?: string;
  /** Whether the filter also names who sends the request, which a simulation cannot know. */
  readonly dependsOnRequester: boolean;
}

const requesterOf = (filter: Json): string | undefined => {
  const parts = [
    ...asArray<Json>(filter.subjects).map((subject) => `${subject.kind} ${subject.namespace ? `${subject.namespace}/` : ""}${subject.name}`),
    ...asArray<string>(filter.roles).map((role) => `role ${role}`),
    ...asArray<string>(filter.clusterRoles).map((role) => `cluster role ${role}`),
  ];

  return parts.length > 0 ? parts.join(", ") : undefined;
};

const evaluateFilter = (filter: Json, target: SimulationTarget): FilterVerdict => {
  const resources = filter.resources ?? {};
  const reasons: string[] = [];
  const caveats: string[] = [];
  const requester = requesterOf(filter);
  const fail = (failure: string): FilterVerdict => ({ matches: false, reasons, caveats, failure, dependsOnRequester: Boolean(requester) });

  const kinds = asArray<string>(resources.kinds);

  if (kinds.length > 0) {
    const matched = kinds.find((spec) => kindSpecMatches(parseKindSpec(spec), target));

    if (!matched) return fail(`kind ${target.kind} is not among ${kinds.join(", ")}`);

    reasons.push(matched === "*" ? "any kind" : `kind ${matched}`);
  }

  const names = [...asArray<string>(resources.names), ...asArray<string>(resources.name)];

  if (names.length > 0) {
    if (target.name === undefined) caveats.push(`only resources named ${names.join(", ")}`);
    else if (!names.some((pattern) => matchesWildcard(pattern, target.name!))) return fail(`name ${target.name} is not among ${names.join(", ")}`);
    else reasons.push(`name matches ${names.join(", ")}`);
  }

  const namespaces = asArray<string>(resources.namespaces);

  if (namespaces.length > 0) {
    if (target.namespace === undefined) return fail(`it only covers namespaces ${namespaces.join(", ")}`);
    if (!namespaces.some((pattern) => matchesWildcard(pattern, target.namespace!))) {
      return fail(`namespace ${target.namespace} is not among ${namespaces.join(", ")}`);
    }

    reasons.push(`namespace in ${namespaces.join(", ")}`);
  }

  if (resources.selector) {
    if (!matchesSelector(resources.selector as LabelSelector, target.labels)) return fail(`labels do not match ${describeSelector(resources.selector)}`);

    reasons.push(`labels match ${describeSelector(resources.selector)}`);
  }

  if (resources.namespaceSelector) {
    if (target.namespace === undefined) return fail("it only covers namespaced resources");
    if (!matchesSelector(resources.namespaceSelector as LabelSelector, target.namespaceLabels)) {
      return fail(`namespace labels do not match ${describeSelector(resources.namespaceSelector)}`);
    }

    reasons.push(`namespace labels match ${describeSelector(resources.namespaceSelector)}`);
  }

  const operations = asArray<string>(resources.operations);

  if (operations.length > 0) {
    if (!operations.includes(target.operation)) return fail(`it only covers ${operations.join(", ")}`);

    reasons.push(`on ${operations.join(", ")}`);
  }

  if (resources.annotations) caveats.push(`only resources annotated ${Object.entries(resources.annotations).map(([key, value]) => `${key}=${value}`).join(", ")}`);

  if (requester) caveats.push(`only requests from ${requester}`);

  return { matches: true, reasons, caveats, dependsOnRequester: Boolean(requester) };
};

/** A `match` or `exclude` block: `{ any: [...] }`, `{ all: [...] }`, or a single filter in the old flat form. */
const filtersOf = (block: Json): { mode: "any" | "all"; filters: Json[] } => {
  if (!block) return { mode: "any", filters: [] };
  if (block.any) return { mode: "any", filters: asArray(block.any) };
  if (block.all) return { mode: "all", filters: asArray(block.all) };

  return { mode: "all", filters: [block] };
};

const describeFilter = (filter: Json): string => {
  const resources = filter.resources ?? {};
  const parts: string[] = [];

  if (resources.kinds) parts.push(asArray(resources.kinds).join(", "));
  else parts.push("any kind");
  if (resources.names || resources.name) parts.push(`named ${[...asArray(resources.names), ...asArray(resources.name)].join(", ")}`);
  if (resources.namespaces) parts.push(`in namespaces ${asArray(resources.namespaces).join(", ")}`);
  if (resources.selector) parts.push(`labelled ${describeSelector(resources.selector)}`);
  if (resources.namespaceSelector) parts.push(`in namespaces labelled ${describeSelector(resources.namespaceSelector)}`);
  if (resources.operations) parts.push(`on ${asArray(resources.operations).join(", ")}`);

  const requester = requesterOf(filter);

  if (requester) parts.push(`sent by ${requester}`);

  return parts.join(" ");
};

const describeMatchBlock = (block: Json, lead: string): string[] => {
  const { mode, filters } = filtersOf(block);

  if (filters.length === 0) return [];
  if (filters.length === 1) return [`${lead} ${describeFilter(filters[0])}`];

  return [`${lead} ${mode === "any" ? "any" : "all"} of:`, ...filters.map((filter) => `  • ${describeFilter(filter)}`)];
};

const evaluateMatch = (match: Json, exclude: Json, target: SimulationTarget): MatchOutcome => {
  const included = filtersOf(match);

  if (included.filters.length === 0) return { applies: false, reason: "the rule matches nothing" };

  const verdicts = included.filters.map((filter) => evaluateFilter(filter, target));
  const reasons: string[] = [];
  const caveats: string[] = [];

  if (included.mode === "any") {
    const hit = verdicts.find((verdict) => verdict.matches);

    if (!hit) return { applies: false, reason: verdicts[0]?.failure ?? "no match" };

    reasons.push(...hit.reasons);
    caveats.push(...hit.caveats);
  } else {
    const miss = verdicts.find((verdict) => !verdict.matches);

    if (miss) return { applies: false, reason: miss.failure ?? "no match" };

    verdicts.forEach((verdict) => {
      reasons.push(...verdict.reasons);
      caveats.push(...verdict.caveats);
    });
  }

  const excluded = filtersOf(exclude);

  if (excluded.filters.length > 0) {
    const exclusions = excluded.filters.map((filter) => ({ filter, verdict: evaluateFilter(filter, target) }));
    const definite = (entry: (typeof exclusions)[number]) => entry.verdict.matches && !entry.verdict.dependsOnRequester && entry.verdict.caveats.length === 0;
    const isExcluded = excluded.mode === "any" ? exclusions.some(definite) : exclusions.every(definite);

    if (isExcluded) return { applies: false, reason: `excluded: ${describeFilter((exclusions.find(definite) ?? exclusions[0]!).filter)}` };

    for (const entry of exclusions) {
      if (entry.verdict.matches) caveats.push(`except ${describeFilter(entry.filter)}`);
    }
  }

  return { applies: true, reasons, caveats };
};

// ---------------------------------------------------------------------------------------------
// Failure actions
// ---------------------------------------------------------------------------------------------

const effectOfAction = (action: unknown): PolicyEffect => (String(action ?? "Audit").toLowerCase() === "enforce" ? "enforce" : "audit");

const overrideApplies = (override: Json, namespace: string | undefined, namespaceLabels: Readonly<Record<string, string>>) =>
  (asArray<string>(override.namespaces).length > 0 && namespace !== undefined && asArray<string>(override.namespaces).some((pattern) => matchesWildcard(pattern, namespace))) ||
  (override.namespaceSelector && namespace !== undefined && matchesSelector(override.namespaceSelector, namespaceLabels));

const effectFor = (base: PolicyEffect, overrides: Json[]) => (namespace: string | undefined, namespaceLabels: Readonly<Record<string, string>>) => {
  const override = overrides.find((candidate) => overrideApplies(candidate, namespace, namespaceLabels));

  return override ? effectOfAction(override.action) : base;
};

// ---------------------------------------------------------------------------------------------
// Classic policies
// ---------------------------------------------------------------------------------------------

const annotationsOf = (resource: Json): Record<string, string> => resource?.metadata?.annotations ?? {};

const readyOf = (resource: Json): NormalizedPolicy["ready"] => {
  const condition = asArray<Json>(resource?.status?.conditions).find((candidate) => candidate.type === "Ready");

  if (condition) return { ok: condition.status === "True", message: condition.message };
  if (typeof resource?.status?.ready === "boolean") return { ok: resource.status.ready };

  return undefined;
};

const ruleTypeOf = (rule: Json) =>
  rule.validate ? "validate" : rule.mutate ? "mutate" : rule.generate ? "generate" : rule.verifyImages ? "verifyImages" : "unknown";

/** A kyverno.io ClusterPolicy or Policy. */
export const normalizeKyvernoPolicy = (resource: Json): NormalizedPolicy => {
  const namespaced = resource.kind === "Policy";
  const ref: PolicyRef = {
    engine: "kyverno",
    kind: namespaced ? "Policy" : "ClusterPolicy",
    name: resource.metadata.name,
    namespace: namespaced ? resource.metadata.namespace : undefined,
  };
  const spec = resource.spec ?? {};
  const annotations = annotationsOf(resource);
  const policyOverrides = asArray<Json>(spec.validationFailureActionOverrides);
  const admissionDisabled = spec.admission === false;
  const notes: string[] = [];

  if (admissionDisabled) notes.push("Admission is turned off for this policy: it only reports through background scans.");
  if (spec.emitWarning) notes.push("Also returns its results to the client as warnings.");
  if (spec.failurePolicy === "Ignore") notes.push("failurePolicy Ignore: requests are let through when Kyverno cannot be reached.");

  const toRule = (rule: Json, autogen: boolean): NormalizedRule => {
    const type = ruleTypeOf(rule);
    let base: PolicyEffect;
    let overrides: Json[] = [];
    let requirements: Requirement[] = [];

    switch (type) {
      case "validate":
        base = effectOfAction(rule.validate.failureAction ?? spec.validationFailureAction);
        overrides = [...asArray<Json>(rule.validate.failureActionOverrides), ...policyOverrides];
        requirements = describeValidate(rule.validate);
        break;
      case "verifyImages": {
        const entries = asArray<Json>(rule.verifyImages);

        base = effectOfAction(entries[0]?.failureAction ?? entries[0]?.validationFailureAction ?? spec.validationFailureAction);
        overrides = policyOverrides;
        requirements = entries.flatMap(describeVerifyImages);
        break;
      }
      case "mutate":
        base = "mutate";
        requirements = describeMutate(rule.mutate);
        break;
      case "generate":
        base = "generate";
        requirements = describeGenerate(rule.generate);
        break;
      default:
        base = "audit";
        requirements = [{ text: "A rule of a type this view does not know", code: code(rule), codeLanguage: "json" }];
    }

    if (admissionDisabled && (base === "enforce" || base === "warn")) base = "audit";

    const conditions = [
      ...describeConditionBlock(rule.preconditions, "Only when").map((requirement) => `${requirement.text} ${requirement.code}`),
      ...(rule.celPreconditions ? asArray<Json>(rule.celPreconditions).map((condition) => `Only when CEL ${condition.expression}`) : []),
    ];

    return {
      id: `${policyRefKey(ref)}#${rule.name}`,
      policy: ref,
      name: rule.name,
      type,
      effect: base,
      effectIn: admissionDisabled ? () => base : effectFor(base, overrides),
      message: rule.validate?.message,
      scope: [
        ...(namespaced ? [`Only in namespace ${ref.namespace}`] : []),
        ...describeMatchBlock(rule.match, "Applies to"),
        ...describeMatchBlock(rule.exclude, "Except"),
      ],
      requirements,
      conditions,
      autogen,
      check: (resource, operation) => checkKyvernoRule(rule, resource, operation),
      matches: (target) => {
        if (namespaced && target.namespace !== ref.namespace) {
          return { applies: false, reason: `the policy is namespaced to ${ref.namespace}` };
        }

        const outcome = evaluateMatch(rule.match, rule.exclude, target);

        return outcome.applies && conditions.length > 0 ? { ...outcome, caveats: [...outcome.caveats, ...conditions] } : outcome;
      },
    };
  };

  const rawAutogenRules = asArray<Json>(resource.status?.autogen?.rules);
  const rules = asArray<Json>(spec.rules).map((rule) => toRule(rule, false));
  const autogenRules = rawAutogenRules.map((rule) => toRule(rule, true));

  if (rawAutogenRules.length > 0) {
    const kinds = new Set(
      rawAutogenRules.flatMap((rule) =>
        filtersOf(rule.match).filters.flatMap((filter) => asArray<string>(filter.resources?.kinds).map((kind) => parseKindSpec(kind).kind)),
      ),
    );

    notes.push(`Kyverno also applies its Pod rules to the controllers that create pods: ${[...kinds].join(", ")}.`);
  }

  return {
    ref,
    title: annotations["policies.kyverno.io/title"] ?? resource.metadata.name,
    description: annotations["policies.kyverno.io/description"],
    category: annotations["policies.kyverno.io/category"],
    severity: annotations["policies.kyverno.io/severity"],
    ready: readyOf(resource),
    rules: [...rules, ...autogenRules],
    background: spec.background !== false,
    notes,
    raw: resource,
  };
};

// ---------------------------------------------------------------------------------------------
// Autogen, for policies Kyverno has not seen yet
// ---------------------------------------------------------------------------------------------

/** The controllers Kyverno writes Pod rules out for, as 1.19 lists them in a policy's status. */
const autogenControllers = ["apps/v1/DaemonSet", "apps/v1/Deployment", "batch/v1/Job", "apps/v1/ReplicaSet", "v1/ReplicationController", "apps/v1/StatefulSet"];

const ruleIsForPodsOnly = (rule: Json) => {
  if (rule.generate) return false;

  const filters = [...filtersOf(rule.match).filters, ...filtersOf(rule.exclude).filters];
  const matchKinds = filtersOf(rule.match).filters.flatMap((filter) => asArray<string>(filter.resources?.kinds));

  return (
    matchKinds.length > 0 &&
    matchKinds.every((kind) => parseKindSpec(kind).kind === "Pod" && !parseKindSpec(kind).subresource) &&
    filters.every((filter) => !filter.resources?.name && !filter.resources?.names && !filter.resources?.selector && !filter.resources?.annotations)
  );
};

const rewriteKinds = (block: Json, kinds: string[]): Json => {
  if (!block) return block;

  const rewrite = (filter: Json) =>
    filter.resources?.kinds ? { ...filter, resources: { ...filter.resources, kinds } } : filter;

  if (block.any) return { ...block, any: asArray<Json>(block.any).map(rewrite) };
  if (block.all) return { ...block, all: asArray<Json>(block.all).map(rewrite) };

  return rewrite(block);
};

const autogenRuleOf = (rule: Json, name: string, kinds: string[], podPath: string[]): Json => {
  const wrap = (pattern: Json) => podPath.reduceRight((inner, key) => ({ [key]: inner }), pattern);
  // Variables that read the pod read its template instead, as Kyverno rewrites them.
  const templatePath = `request.object.${podPath.join(".")}`;
  const retarget = (value: Json) =>
    value === undefined ? value : JSON.parse(JSON.stringify(value).replace(/request\.object\.(spec|metadata)\b/g, `${templatePath}.$1`));
  const validate = rule.validate
    ? {
        ...retarget(rule.validate),
        ...(rule.validate.pattern !== undefined ? { pattern: wrap(retarget(rule.validate.pattern)) } : {}),
        ...(rule.validate.anyPattern !== undefined ? { anyPattern: asArray<Json>(rule.validate.anyPattern).map((pattern) => wrap(retarget(pattern))) } : {}),
      }
    : undefined;

  return {
    ...rule,
    name,
    match: rewriteKinds(rule.match, kinds),
    exclude: rewriteKinds(rule.exclude, kinds),
    preconditions: retarget(rule.preconditions),
    ...(validate ? { validate } : {}),
  };
};

/**
 * A policy with the autogen rules Kyverno would add once it admitted it: each Pod rule written out
 * for the controllers that create pods, and for CronJobs. A policy that already carries them in its
 * status, as one read from the cluster does, is returned as it is.
 */
export const withAutogenRules = (resource: Json): Json => {
  if (resource?.status?.autogen?.rules) return resource;

  const setting = String(resource?.metadata?.annotations?.["pod-policies.kyverno.io/autogen-controllers"] ?? "");

  if (setting.trim().toLowerCase() === "none") return resource;

  const wanted = setting ? new Set(setting.split(",").map((controller) => controller.trim())) : undefined;
  const controllers = autogenControllers.filter((controller) => !wanted || wanted.has(controller.split("/").pop()!));
  const rules = asArray<Json>(resource?.spec?.rules)
    .filter(ruleIsForPodsOnly)
    .flatMap((rule) => [
      ...(controllers.length > 0 ? [autogenRuleOf(rule, `autogen-${rule.name}`, controllers, ["spec", "template"])] : []),
      ...(!wanted || wanted.has("CronJob") ? [autogenRuleOf(rule, `autogen-cronjob-${rule.name}`, ["batch/v1/CronJob"], ["spec", "jobTemplate", "spec", "template"])] : []),
    ]);

  return rules.length > 0 ? { ...resource, status: { ...resource.status, autogen: { rules } } } : resource;
};

// ---------------------------------------------------------------------------------------------
// CEL policies of policies.kyverno.io
// ---------------------------------------------------------------------------------------------

const resourceRuleMatches = (rule: Json, target: SimulationTarget) => {
  const groups = asArray<string>(rule.apiGroups);
  const resources = asArray<string>(rule.resources);
  const operations = asArray<string>(rule.operations);
  const names = asArray<string>(rule.resourceNames);

  return (
    (groups.length === 0 || groups.includes("*") || groups.includes(target.group)) &&
    resources.some((resource) => resource === "*" || resource === target.resource) &&
    (operations.length === 0 || operations.includes("*") || operations.includes(target.operation)) &&
    (names.length === 0 || target.name === undefined || names.includes(target.name))
  );
};

const describeResourceRule = (rule: Json) =>
  `${asArray(rule.resources).join(", ")}${asArray<string>(rule.apiGroups).some((group) => group !== "") ? ` (${asArray<string>(rule.apiGroups).map((group) => group || "core").join(", ")})` : ""} on ${
    asArray(rule.operations).join(", ") || "any operation"
  }`;

/** Matching the way ValidatingAdmissionPolicy's matchConstraints does, which Kyverno's CEL policies reuse. */
export const evaluateMatchConstraints = (constraints: Json, target: SimulationTarget): MatchOutcome => {
  const rules = asArray<Json>(constraints?.resourceRules);

  if (rules.length === 0) return { applies: false, reason: "it names no resources" };

  const hit = rules.find((rule) => resourceRuleMatches(rule, target));

  if (!hit) return { applies: false, reason: `${target.resource} on ${target.operation} is not among ${rules.map(describeResourceRule).join("; ")}` };

  const excluded = asArray<Json>(constraints.excludeResourceRules).find((rule) => resourceRuleMatches(rule, target));

  if (excluded) return { applies: false, reason: `excluded: ${describeResourceRule(excluded)}` };

  const reasons = [describeResourceRule(hit)];

  if (constraints.namespaceSelector && target.namespace !== undefined) {
    if (!matchesSelector(constraints.namespaceSelector, target.namespaceLabels)) {
      return { applies: false, reason: `namespace labels do not match ${describeSelector(constraints.namespaceSelector)}` };
    }

    if (Object.keys(constraints.namespaceSelector.matchLabels ?? {}).length || (constraints.namespaceSelector.matchExpressions ?? []).length) {
      reasons.push(`namespace labels match ${describeSelector(constraints.namespaceSelector)}`);
    }
  }

  if (constraints.objectSelector && !matchesSelector(constraints.objectSelector, target.labels)) {
    return { applies: false, reason: `labels do not match ${describeSelector(constraints.objectSelector)}` };
  }

  return { applies: true, reasons, caveats: [] };
};

const describeMatchConstraints = (constraints: Json): string[] => {
  const lines = asArray<Json>(constraints?.resourceRules).map((rule) => `Applies to ${describeResourceRule(rule)}`);

  for (const rule of asArray<Json>(constraints?.excludeResourceRules)) lines.push(`Except ${describeResourceRule(rule)}`);
  if (constraints?.namespaceSelector) lines.push(`In namespaces labelled ${describeSelector(constraints.namespaceSelector, "any")}`);
  if (constraints?.objectSelector) lines.push(`Labelled ${describeSelector(constraints.objectSelector, "anything")}`);

  return lines;
};

const effectOfValidationActions = (actions: string[]): PolicyEffect =>
  actions.includes("Deny") ? "enforce" : actions.includes("Warn") ? "warn" : "audit";

/** A policies.kyverno.io ValidatingPolicy or NamespacedValidatingPolicy. */
export const normalizeKyvernoCelPolicy = (resource: Json): NormalizedPolicy => {
  const namespaced = resource.kind === "NamespacedValidatingPolicy";
  const ref: PolicyRef = {
    engine: "kyverno-cel",
    kind: resource.kind,
    name: resource.metadata.name,
    namespace: namespaced ? resource.metadata.namespace : undefined,
  };
  const spec = resource.spec ?? {};
  const annotations = annotationsOf(resource);
  const actions = asArray<string>(spec.validationActions);
  const effect = effectOfValidationActions(actions);
  const admissionDisabled = spec.evaluation?.admission?.enabled === false;
  const notes: string[] = [];

  if (actions.length === 0) notes.push("No validationActions set: shown as auditing.");
  if (admissionDisabled) notes.push("Admission is turned off for this policy: it only reports through background scans.");
  if (spec.failurePolicy === "Ignore") notes.push("failurePolicy Ignore: requests are let through when the policy cannot be evaluated.");

  const conditions = asArray<Json>(spec.matchConditions).map((condition) => `Only when ${condition.name}: ${condition.expression}`);
  const variables = asArray<Json>(spec.variables);
  const requirements: Requirement[] = [
    ...variables.map((variable) => ({ text: `With variable ${variable.name}`, code: variable.expression, codeLanguage: "cel" as const })),
    ...asArray<Json>(spec.validations).map((validation) => ({
      text: validation.message ?? (validation.messageExpression ? `Must satisfy (message: ${validation.messageExpression})` : "Must satisfy"),
      code: validation.expression,
      codeLanguage: "cel" as const,
    })),
  ];
  const finalEffect = admissionDisabled ? "audit" : effect;

  return {
    ref,
    title: annotations["policies.kyverno.io/title"] ?? resource.metadata.name,
    description: annotations["policies.kyverno.io/description"],
    category: annotations["policies.kyverno.io/category"],
    severity: annotations["policies.kyverno.io/severity"],
    ready: readyOf(resource),
    background: spec.evaluation?.background?.enabled !== false,
    notes,
    raw: resource,
    rules: [
      {
        id: `${policyRefKey(ref)}#validations`,
        policy: ref,
        name: "validations",
        type: "cel",
        effect: finalEffect,
        effectIn: () => finalEffect,
        scope: [...(namespaced ? [`Only in namespace ${ref.namespace}`] : []), ...describeMatchConstraints(spec.matchConstraints)],
        requirements,
        conditions,
        matches: (target) => {
          if (namespaced && target.namespace !== ref.namespace) return { applies: false, reason: `the policy is namespaced to ${ref.namespace}` };

          const outcome = evaluateMatchConstraints(spec.matchConstraints, target);

          return outcome.applies && conditions.length > 0 ? { ...outcome, caveats: [...outcome.caveats, ...conditions] } : outcome;
        },
      },
    ],
  };
};

// ---------------------------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------------------------

export interface PolicyExemption {
  readonly exception: { readonly name: string; readonly namespace?: string };
  /** Whether the exemption holds for the target for sure, or only under conditions the request settles. */
  readonly certain: boolean;
  readonly condition?: string;
}

export interface NormalizedException {
  readonly name: string;
  readonly namespace?: string;
  readonly exempts: (rule: NormalizedRule, target: SimulationTarget) => PolicyExemption | undefined;
  readonly summary: string[];
}

const policyNameAsExceptionsSayIt = (ref: PolicyRef) => (ref.namespace ? `${ref.namespace}/${ref.name}` : ref.name);

/** kyverno.io/v2 PolicyException: named policies and rules, for resources its match block covers. */
export const normalizeKyvernoException = (resource: Json): NormalizedException => {
  const spec = resource.spec ?? {};
  const exceptions = asArray<Json>(spec.exceptions);
  const conditions = describeConditionBlock(spec.conditions, "Only when").map((requirement) => `${requirement.text} ${requirement.code}`);

  return {
    name: resource.metadata.name,
    namespace: resource.metadata.namespace,
    summary: [
      ...exceptions.map((entry) => `Exempts ${entry.policyName}${entry.ruleNames ? ` (rules ${asArray(entry.ruleNames).join(", ")})` : ""}`),
      ...describeMatchBlock(spec.match, "For"),
      ...conditions,
    ],
    exempts: (rule, target) => {
      if (rule.policy.engine !== "kyverno") return undefined;

      const entry = exceptions.find(
        (candidate) =>
          candidate.policyName === policyNameAsExceptionsSayIt(rule.policy) &&
          asArray<string>(candidate.ruleNames).some((name) => matchesWildcard(name, rule.name) || matchesWildcard(name, rule.name.replace(/^autogen-(cronjob-)?/, ""))),
      );

      if (!entry) return undefined;

      const outcome = evaluateMatch(spec.match, undefined, target);

      if (!outcome.applies) return undefined;

      const caveats = [...outcome.caveats, ...conditions];

      return {
        exception: { name: resource.metadata.name, namespace: resource.metadata.namespace },
        certain: caveats.length === 0,
        condition: caveats.join("; ") || undefined,
      };
    },
  };
};

/** policies.kyverno.io/v1 PolicyException: named CEL policies, for requests its CEL conditions accept. */
export const normalizeKyvernoCelException = (resource: Json): NormalizedException => {
  const spec = resource.spec ?? {};
  const refs = asArray<Json>(spec.policyRefs);
  const conditions = asArray<Json>(spec.matchConditions).map((condition) => `${condition.name}: ${condition.expression}`);

  return {
    name: resource.metadata.name,
    namespace: resource.metadata.namespace,
    summary: [...refs.map((entry) => `Exempts ${entry.kind ?? "policy"} ${entry.name}`), ...conditions.map((condition) => `When ${condition}`)],
    exempts: (rule) => {
      if (rule.policy.engine !== "kyverno-cel") return undefined;
      if (!refs.some((entry) => entry.name === rule.policy.name && (!entry.kind || entry.kind === rule.policy.kind))) return undefined;

      return {
        exception: { name: resource.metadata.name, namespace: resource.metadata.namespace },
        certain: conditions.length === 0,
        condition: conditions.join("; ") || undefined,
      };
    },
  };
};
