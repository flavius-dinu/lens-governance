/** Kubernetes label selectors: matching and describing them. */

export type Labels = Readonly<Record<string, string>>;

export interface LabelSelectorRequirement {
  readonly key: string;
  readonly operator: string;
  readonly values?: readonly string[] | null;
}

export interface LabelSelector {
  readonly matchLabels?: Readonly<Record<string, string>> | null;
  readonly matchExpressions?: readonly LabelSelectorRequirement[] | null;
}

/** Whether `labels` satisfy `selector`. An empty selector matches everything. */
export const matchesSelector = (
  selector: LabelSelector | null | undefined,
  labels: Labels,
  normalizeKey: (key: string) => string = (key) => key,
): boolean => {
  if (!selector) return true;

  for (const [rawKey, value] of Object.entries(selector.matchLabels ?? {})) {
    if (labels[normalizeKey(rawKey)] !== value) return false;
  }

  for (const requirement of selector.matchExpressions ?? []) {
    const key = normalizeKey(requirement.key);
    const has = Object.prototype.hasOwnProperty.call(labels, key);
    const values = requirement.values ?? [];

    switch (requirement.operator) {
      case "In":
        if (!has || !values.includes(labels[key]!)) return false;
        break;
      case "NotIn":
        if (has && values.includes(labels[key]!)) return false;
        break;
      case "Exists":
        if (!has) return false;
        break;
      case "DoesNotExist":
        if (has) return false;
        break;
      default:
        // An operator we do not know selects nothing, as the API server would refuse it anyway.
        return false;
    }
  }

  return true;
};

export const isEmptySelector = (selector: LabelSelector | null | undefined) =>
  !selector || (Object.keys(selector.matchLabels ?? {}).length === 0 && (selector.matchExpressions ?? []).length === 0);

/** `app=web, tier in (a,b), !legacy`, or `everything` for an empty selector. */
export const describeSelector = (selector: LabelSelector | null | undefined, everything = "all"): string => {
  if (isEmptySelector(selector)) return everything;

  const parts = Object.entries(selector!.matchLabels ?? {}).map(([key, value]) => `${key}=${value}`);

  for (const requirement of selector!.matchExpressions ?? []) {
    const values = (requirement.values ?? []).join(",");

    switch (requirement.operator) {
      case "In":
        parts.push(`${requirement.key} in (${values})`);
        break;
      case "NotIn":
        parts.push(`${requirement.key} notin (${values})`);
        break;
      case "Exists":
        parts.push(requirement.key);
        break;
      case "DoesNotExist":
        parts.push(`!${requirement.key}`);
        break;
      default:
        parts.push(`${requirement.key} ${requirement.operator} (${values})`);
    }
  }

  return parts.join(", ");
};

/** Parses `a=b, c=d` (also `a: b`) as typed by a user into labels. */
export const parseLabels = (text: string): Record<string, string> => {
  const labels: Record<string, string> = {};

  for (const part of text.split(/[,\n]/)) {
    const trimmed = part.trim();

    if (!trimmed) continue;

    const match = /^([^=:\s]+)\s*[=:]\s*(.*)$/.exec(trimmed);

    if (match) labels[match[1]!] = match[2]!.trim();
    else labels[trimmed] = "";
  }

  return labels;
};

/** Glob matching as Kyverno and Gatekeeper use it for names and namespaces: `*` and `?`. */
export const matchesWildcard = (pattern: string, value: string): boolean => {
  if (!pattern.includes("*") && !pattern.includes("?")) return pattern === value;

  const regex = new RegExp(
    `^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`,
    "s",
  );

  return regex.test(value);
};
