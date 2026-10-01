/**
 * Which admission rules a resource would meet, and what each would do to it: the question "what
 * restrictions apply to a Deployment in namespace payments labelled team=checkout?".
 */

import { namespaceIsExcludedByConfig } from "./gatekeeper";
import type { NormalizedException, PolicyExemption } from "./kyverno";
import type { NormalizedPolicy, NormalizedRule, PolicyEffect, SimulationTarget } from "./model";

export interface ApplicableRule {
  readonly rule: NormalizedRule;
  readonly policy: NormalizedPolicy;
  readonly effect: PolicyEffect;
  readonly reasons: readonly string[];
  readonly caveats: readonly string[];
  /** An exception that may exempt the resource, when its conditions hold. */
  readonly possibleExemption?: PolicyExemption;
}

export interface SkippedRule {
  readonly rule: NormalizedRule;
  readonly policy: NormalizedPolicy;
  readonly reason: string;
}

export interface Simulation {
  readonly applicable: readonly ApplicableRule[];
  readonly skipped: readonly SkippedRule[];
  readonly byEffect: Readonly<Record<PolicyEffect, readonly ApplicableRule[]>>;
}

export interface SimulationContext {
  readonly policies: readonly NormalizedPolicy[];
  readonly exceptions: readonly NormalizedException[];
  /** Namespaces the Gatekeeper Config keeps out of admission. */
  readonly gatekeeperExcludedNamespaces: readonly string[];
}

const effects: readonly PolicyEffect[] = ["enforce", "warn", "audit", "mutate", "generate"];

export const simulate = (context: SimulationContext, target: SimulationTarget): Simulation => {
  const applicable: ApplicableRule[] = [];
  const skipped: SkippedRule[] = [];
  const gatekeeperExclusion = namespaceIsExcludedByConfig(context.gatekeeperExcludedNamespaces, target.namespace);

  for (const policy of context.policies) {
    for (const rule of policy.rules) {
      if (policy.ref.engine === "gatekeeper" && gatekeeperExclusion) {
        skipped.push({ rule, policy, reason: `the Gatekeeper Config excludes namespace ${target.namespace} (${gatekeeperExclusion})` });
        continue;
      }

      const outcome = rule.matches(target);

      if (!outcome.applies) {
        skipped.push({ rule, policy, reason: outcome.reason });
        continue;
      }

      const exemptions = context.exceptions.map((exception) => exception.exempts(rule, target)).filter((exemption) => exemption !== undefined);
      const certain = exemptions.find((exemption) => exemption.certain);

      if (certain) {
        const where = certain.exception.namespace ? `${certain.exception.namespace}/${certain.exception.name}` : certain.exception.name;

        skipped.push({ rule, policy, reason: `exempted by PolicyException ${where}` });
        continue;
      }

      applicable.push({
        rule,
        policy,
        effect: rule.effectIn(target.namespace, target.namespaceLabels),
        reasons: outcome.reasons,
        caveats: outcome.caveats,
        possibleExemption: exemptions[0],
      });
    }
  }

  const byEffect = Object.fromEntries(effects.map((effect) => [effect, applicable.filter((entry) => entry.effect === effect)])) as Record<
    PolicyEffect,
    ApplicableRule[]
  >;

  return { applicable, skipped, byEffect };
};
