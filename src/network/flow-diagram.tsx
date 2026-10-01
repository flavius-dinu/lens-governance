/** The picture of a simulated flow: who talks to whom, and which side's policy lets it through or stops it. */

import { Svg } from "@k8slens/element-components";
import type { FlowVerdict, ServiceVerdict, SideVerdict } from "../engines/net/evaluate";
import { type Endpoint } from "../engines/net/model";
import styles from "../ui/governance.module.scss";

const truncate = (text: string, length: number) => (text.length > length ? `${text.slice(0, length - 1)}…` : text);

const gateCaption = (side: SideVerdict | undefined) => {
  if (!side) return "outside the cluster";

  switch (side.reason) {
    case "not-isolated":
      return side.trace.length === 0 ? "no policy: open" : "not isolated";
    case "allowed-by-rule":
      return `allowed: ${side.decidedBy?.policy.ref.name ?? ""}`;
    case "denied-by-rule":
      return `denied: ${side.decidedBy?.policy.ref.name ?? ""}`;
    case "no-rule-allows":
      return "no rule allows it";
    case "end-of-tier":
      return "denied at end of tier";
    case "host-network":
      return "host network: open";
    default:
      return side.summary;
  }
};

const gateClass = (side: SideVerdict | undefined) => (!side ? styles.gateNone : side.allowed ? styles.gateAllowed : styles.gateDenied);

const Gate = ({ x, y, label, side }: { x: number; y: number; label: string; side: SideVerdict | undefined }) => (
  <g>
    <text x={x} y={y - 26} textAnchor="middle" className={styles.muted}>
      {label}
    </text>
    <circle cx={x} cy={y} r={15} className={gateClass(side)}>
      <title>{side?.summary ?? "No policy of this cluster governs this end"}</title>
    </circle>
    <text x={x} y={y + 5} textAnchor="middle" className={styles.gateGlyph}>
      {!side ? "–" : side.allowed ? "✓" : "✕"}
    </text>
    <text x={x} y={y + 34} textAnchor="middle" className={styles.muted}>
      {truncate(gateCaption(side), 24)}
    </text>
  </g>
);

const EndpointBox = ({ x, y, width, endpoint, heading }: { x: number; y: number; width: number; endpoint: Endpoint; heading: string }) => {
  const lines =
    endpoint.type === "pod"
      ? [endpoint.pod.name, `ns ${endpoint.pod.namespace}`, endpoint.pod.ips[0] ?? "no IP yet"]
      : [endpoint.ip, "outside the cluster"];
  const characters = Math.floor(width / 7);

  return (
    <g>
      <rect x={x} y={y} width={width} height={96} rx={8} className={endpoint.type === "pod" ? styles.box : styles.boxExternal} />
      <text x={x + 12} y={y + 22} className={styles.muted}>
        {heading}
      </text>
      <text x={x + 12} y={y + 44} className={styles.title}>
        {truncate(lines[0]!, characters)}
      </text>
      {lines.slice(1).map((line, index) => (
        <text key={line} x={x + 12} y={y + 64 + index * 18} className={styles.muted}>
          {truncate(line, characters)}
        </text>
      ))}
    </g>
  );
};

const Arrow = ({ x, y, allowed }: { x: number; y: number; allowed: boolean | undefined }) => (
  <polygon
    points={`${x - 10},${y - 6} ${x},${y} ${x - 10},${y + 6}`}
    className={allowed === undefined ? styles.arrowNeutral : allowed ? styles.arrowAllowed : styles.arrowDenied}
  />
);

const lineClass = (allowed: boolean | undefined) => (allowed === undefined ? styles.lineNeutral : allowed ? styles.lineAllowed : styles.lineDenied);

export const FlowDiagram = ({ verdict }: { verdict: FlowVerdict }) => {
  const y = 96;

  return (
    <Svg viewBox="0 0 820 200" $className={styles.diagram} role="img" aria-label={`${verdict.allowed ? "Allowed" : "Denied"} flow diagram`}>
      <EndpointBox x={10} y={y - 48} width={230} endpoint={verdict.source} heading="FROM" />
      <EndpointBox x={580} y={y - 48} width={230} endpoint={verdict.destination} heading="TO" />
      <line x1={240} y1={y} x2={578} y2={y} className={lineClass(verdict.allowed)} />
      <Arrow x={580} y={y} allowed={verdict.allowed} />
      <text x={410} y={y - 50} textAnchor="middle" className={styles.title}>
        {verdict.traffic.protocol} {verdict.traffic.port}
      </text>
      <Gate x={330} y={y} label="EGRESS" side={verdict.egress} />
      <Gate x={490} y={y} label="INGRESS" side={verdict.ingress} />
    </Svg>
  );
};

/** At most this many backends are drawn; the table under the diagram lists all of them. */
const drawnBackends = 6;

export const ServiceDiagram = ({ source, verdict }: { source: Endpoint; verdict: ServiceVerdict }) => {
  const backends = verdict.backends.slice(0, drawnBackends);
  const rowHeight = 64;
  const height = Math.max(200, 30 + Math.max(backends.length, 1) * rowHeight);
  const centre = height / 2;

  return (
    <Svg viewBox={`0 0 820 ${height}`} $className={styles.diagram} role="img" aria-label="Service flow diagram">
      <EndpointBox x={10} y={centre - 48} width={200} endpoint={source} heading="FROM" />
      <line x1={210} y1={centre} x2={298} y2={centre} className={styles.lineNeutral} />
      <Arrow x={300} y={centre} allowed={undefined} />
      <rect x={300} y={centre - 40} width={170} height={80} rx={8} className={styles.boxService} />
      <text x={312} y={centre - 18} className={styles.muted}>
        SERVICE
      </text>
      <text x={312} y={centre + 2} className={styles.title}>
        {truncate(verdict.service.name, 22)}
      </text>
      <text x={312} y={centre + 22} className={styles.muted}>
        {verdict.servicePort.protocol} {verdict.servicePort.port} → {String(verdict.servicePort.targetPort)}
      </text>
      {backends.length === 0 && (
        <text x={500} y={centre + 4} className={styles.muted}>
          no backend pods
        </text>
      )}
      {backends.map((backend, index) => {
        const top = 15 + index * rowHeight;
        const middle = top + 24;
        const allowed = backend.verdict?.allowed;
        const failedSide = backend.verdict && !backend.verdict.allowed ? (backend.verdict.egress && !backend.verdict.egress.allowed ? "egress" : "ingress") : undefined;

        return (
          <g key={backend.pod.uid}>
            <path d={`M 470 ${centre} C 520 ${centre}, 520 ${middle}, 588 ${middle}`} className={lineClass(allowed)} />
            <Arrow x={590} y={middle} allowed={allowed} />
            <circle cx={540} cy={middle} r={11} className={allowed === undefined ? styles.gateNone : allowed ? styles.gateAllowed : styles.gateDenied}>
              <title>{[backend.problem ?? backend.verdict?.egress?.summary, backend.verdict?.ingress?.summary].filter(Boolean).join("\n")}</title>
            </circle>
            <text x={540} y={middle + 4} textAnchor="middle" className={styles.gateGlyph}>
              {allowed === undefined ? "?" : allowed ? "✓" : "✕"}
            </text>
            <rect x={592} y={top} width={218} height={48} rx={6} className={styles.box} />
            <text x={604} y={top + 20} className={styles.title}>
              {truncate(backend.pod.name, 27)}
            </text>
            <text x={604} y={top + 38} className={styles.muted}>
              {backend.targetPort !== undefined ? `port ${backend.targetPort}` : (backend.problem ?? "")}
              {failedSide ? ` · blocked at ${failedSide}` : ""}
            </text>
          </g>
        );
      })}
    </Svg>
  );
};
