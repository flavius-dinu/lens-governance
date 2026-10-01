/** The pieces every view is drawn with, built from Lens's own components so they follow the theme. */

import { Badge } from "@k8slens/badge";
import { Code, Div, type DivProps, H2, Pre, Span } from "@k8slens/element-components";
import { ErrorOutlineIcon, InfoOutlineIcon, SpinnerIcon, WarningIcon } from "@k8slens/icon";
import { Component, type ComponentType, type ErrorInfo, type ReactNode } from "react";
import type { PolicyEffect, PolicyEngine } from "../engines/policies/model";
import { effectLabel, engineLabel } from "../engines/policies/model";
import type { Severity } from "../engines/rbac";
import styles from "./governance.module.scss";
import { SearchPicker } from "./search-picker";

type Tone = "success" | "warning" | "critical" | "notice" | "primary" | "grey40" | "grey60";

export const ToneBadge = ({ tone, label, tooltip, small = true }: { tone: Tone; label: ReactNode; tooltip?: string; small?: boolean }) => (
  <Badge small={small} label={label} $backgroundColor={tone} $color="white" $tooltip={tooltip} />
);

const severityTone: Record<Severity, Tone> = { critical: "critical", high: "warning", medium: "notice", low: "grey40" };

export const SeverityBadge = ({ severity }: { severity: Severity }) => <ToneBadge tone={severityTone[severity]} label={severity} />;

const effectTone: Record<PolicyEffect, Tone> = { enforce: "critical", warn: "warning", audit: "notice", mutate: "primary", generate: "grey40" };

export const EffectBadge = ({ effect }: { effect: PolicyEffect }) => <ToneBadge tone={effectTone[effect]} label={effectLabel[effect]} />;

export const EngineBadge = ({ engine }: { engine: PolicyEngine | string }) => (
  <Badge small label={engineLabel[engine as PolicyEngine] ?? engine} $tooltip="Policy engine" />
);

export const VerdictBadge = ({ allowed, small = false }: { allowed: boolean; small?: boolean }) => (
  <ToneBadge tone={allowed ? "success" : "critical"} label={allowed ? "ALLOWED" : "DENIED"} small={small} />
);

export const Page = ({ children }: { children: ReactNode }) => (
  <Div $className={styles.page} $padding={{ horizontal: "xl", vertical: "l" }}>
    <Div $flex={{ direction: "vertical", gap: "l" }}>{children}</Div>
  </Div>
);

export const PageHeader = ({ Icon, title, subtitle, children }: { Icon: ComponentType<{ $size?: "l" }>; title: string; subtitle: string; children?: ReactNode }) => (
  <Div $flex={{ direction: "horizontal", gap: "m", verticalAlign: "center" }}>
    <Span $color="primary">
      <Icon $size="l" />
    </Span>
    <Div $flex={{ direction: "vertical", gap: "xxs" }} $flexChild>
      <H2 $font={{ size: "xl", bold: true }}>{title}</H2>
      <Span $color="textMuted">{subtitle}</Span>
    </Div>
    {children}
  </Div>
);

export const Section = ({ title, actions, children, ...rest }: { title?: ReactNode; actions?: ReactNode; children: ReactNode } & Omit<DivProps, "title">) => (
  <Div
    $flex={{ direction: "vertical", gap: "s" }}
    $padding="m"
    $border={{ color: "borderPrimary", width: "xxs", radius: "m" }}
    $backgroundColor="backgroundPrimary"
    {...rest}
  >
    {(title || actions) && (
      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", horizontalAlign: "space-between", wrap: true }}>
        {title && <Span $font={{ size: "m", bold: true }}>{title}</Span>}
        {actions && <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>{actions}</Div>}
      </Div>
    )}
    {children}
  </Div>
);

export const Notice = ({ tone = "notice", children }: { tone?: "notice" | "warning" | "critical"; children: ReactNode }) => {
  const Icon = tone === "critical" ? ErrorOutlineIcon : tone === "warning" ? WarningIcon : InfoOutlineIcon;

  return (
    <Div
      $flex={{ direction: "horizontal", gap: "s", verticalAlign: "top" }}
      $padding={{ horizontal: "m", vertical: "s" }}
      $border={{ color: tone, width: "xxs", radius: "m" }}
    >
      <Span $color={tone}>
        <Icon $size="s" />
      </Span>
      <Div $flexChild>{children}</Div>
    </Div>
  );
};

export const Muted = ({ children }: { children: ReactNode }) => <Span $color="textMuted">{children}</Span>;

export const InlineCode = ({ children }: { children: ReactNode }) => <Code $className={styles.inlineCode}>{children}</Code>;

/** Text with `backticked` parts set as code, as the engines write their explanations. */
export const RichText = ({ text }: { text: string }) => (
  <>
    {text.split(/(`[^`]*`)/).map((part, index) =>
      part.startsWith("`") && part.endsWith("`") && part.length > 1 ? <InlineCode key={index}>{part.slice(1, -1)}</InlineCode> : <Span key={index}>{part}</Span>,
    )}
  </>
);

export const CodeBlock = ({ code }: { code: string }) => <Pre $className={styles.code}>{code}</Pre>;

export const Empty = ({ children }: { children: ReactNode }) => (
  <Div $padding="l" $textAlign="center">
    <Muted>{children}</Muted>
  </Div>
);

export const Field = ({ label, children, grow }: { label: string; children: ReactNode; grow?: boolean }) => (
  <Div $flex={{ direction: "vertical", gap: "xxs" }} $flexChild={grow ? true : undefined}>
    <Span $font={{ size: "s" }} $color="textMuted">
      {label}
    </Span>
    {children}
  </Div>
);

export interface PickerOption {
  readonly value: string;
  readonly label?: string;
}

/**
 * A text box with the values it suggests in a list under it: all of them when it opens, those
 * matching what is typed after. It still takes any value.
 */
export const Picker = ({
  value,
  onChange,
  options,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  options: readonly PickerOption[];
  placeholder?: string;
}) => (
  <SearchPicker
    value={value}
    onChange={onChange}
    options={options.map((option) => ({ value: option.value, name: option.value, detail: option.label }))}
    placeholder={placeholder}
  />
);

/** Toggles drawn as badges: what to filter by, or which of a few to pick. */
export const Chips = <T extends string>({
  options,
  isSelected,
  onToggle,
}: {
  options: readonly { readonly id: T; readonly label: string; readonly tooltip?: string }[];
  isSelected: (id: T) => boolean;
  onToggle: (id: T) => void;
}) => (
  <Div $flex={{ direction: "horizontal", gap: "xs", wrap: true }}>
    {options.map((option) => (
      <Badge
        key={option.id}
        small
        label={option.label}
        $tooltip={option.tooltip}
        $onClick={() => onToggle(option.id)}
        $backgroundColor={isSelected(option.id) ? "primary" : undefined}
        $color={isSelected(option.id) ? "white" : undefined}
      />
    ))}
  </Div>
);

export const Stat = ({ label, value, tone }: { label: string; value: ReactNode; tone?: Tone }) => (
  <Div $flex={{ direction: "vertical", gap: "zero", horizontalAlign: "center" }} $padding={{ horizontal: "m", vertical: "xs" }}>
    <Span $font={{ size: "xl", bold: true }} $color={tone ?? "textHighlight"}>
      {value}
    </Span>
    <Span $font={{ size: "xs" }} $color="textMuted">
      {label}
    </Span>
  </Div>
);

export interface LoadSnapshot {
  readonly loading: boolean;
  readonly pending?: readonly { readonly label: string }[];
  readonly failures: readonly { readonly label: string; readonly error: string }[];
}

/** Says what is still loading, and what could not be read, so an empty view is never mistaken for an empty cluster. */
export const LoadStatus = ({ snapshot, extraFailures = [] }: { snapshot: LoadSnapshot; extraFailures?: readonly string[] }) => (
  <>
    {snapshot.loading && (
      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center" }}>
        <SpinnerIcon $size="s" />
        <Muted>
          Reading the cluster…
          {snapshot.pending && snapshot.pending.length > 0 ? ` waiting for ${snapshot.pending.map((entry) => entry.label.toLowerCase()).join(", ")}` : ""}
        </Muted>
      </Div>
    )}
    {(snapshot.failures.length > 0 || extraFailures.length > 0) && (
      <Notice tone="warning">
        <Div $flex={{ direction: "vertical", gap: "xxs" }}>
          <Span $font={{ bold: true }}>Some of the cluster could not be read, so what follows is incomplete:</Span>
          {snapshot.failures.map((failure) => (
            <Span key={failure.label} $font={{ size: "s" }}>
              {failure.label}: {failure.error}
            </Span>
          ))}
          {extraFailures.map((failure) => (
            <Span key={failure} $font={{ size: "s" }}>
              {failure}
            </Span>
          ))}
        </Div>
      </Notice>
    )}
  </>
);

interface BoundaryState {
  readonly error?: Error;
}

/** Keeps a failure in one view from reaching the rest of Lens, and says what failed. */
export class ErrorBoundary extends Component<{ children: ReactNode; label: string }, BoundaryState> {
  override state: BoundaryState = {};

  static getDerivedStateFromError(error: Error): BoundaryState {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[real-governance] ${this.props.label} failed`, error, info.componentStack);
  }

  override render() {
    if (!this.state.error) return this.props.children;

    return (
      <Div $padding="l">
        <Notice tone="critical">
          <Div $flex={{ direction: "vertical", gap: "xs" }}>
            <Span $font={{ bold: true }}>{this.props.label} could not be shown.</Span>
            <Span $font={{ size: "s" }}>{this.state.error.message}</Span>
          </Div>
        </Notice>
      </Div>
    );
  }
}

export const plural = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;
