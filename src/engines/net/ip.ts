/** IPv4 and IPv6 addresses and CIDR blocks, compared as integers. */

interface ParsedIp {
  readonly version: 4 | 6;
  readonly value: bigint;
}

const parseIpv4 = (text: string): bigint | undefined => {
  const parts = text.split(".");

  if (parts.length !== 4) return undefined;

  let value = 0n;

  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined;

    const octet = Number(part);

    if (octet > 255) return undefined;

    value = (value << 8n) | BigInt(octet);
  }

  return value;
};

const parseIpv6 = (text: string): bigint | undefined => {
  let address = text;
  const lastColon = address.lastIndexOf(":");

  // An embedded IPv4 tail, as in ::ffff:10.0.0.1, stands for the last two groups.
  if (address.slice(lastColon + 1).includes(".")) {
    const v4 = parseIpv4(address.slice(lastColon + 1));

    if (v4 === undefined) return undefined;

    address = `${address.slice(0, lastColon + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }

  const halves = address.split("::");

  if (halves.length > 2) return undefined;

  const groupsOf = (half: string) => (half === "" ? [] : half.split(":"));
  const head = groupsOf(halves[0]!);
  const rest = halves.length === 2 ? groupsOf(halves[1]!) : [];
  const missing = 8 - head.length - rest.length;

  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;

  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...rest];
  let value = 0n;

  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return undefined;

    value = (value << 16n) | BigInt(parseInt(group, 16));
  }

  return value;
};

export const parseIp = (text: string): ParsedIp | undefined => {
  const trimmed = text.trim();
  const v4 = parseIpv4(trimmed);

  if (v4 !== undefined) return { version: 4, value: v4 };

  const v6 = trimmed.includes(":") ? parseIpv6(trimmed) : undefined;

  return v6 !== undefined ? { version: 6, value: v6 } : undefined;
};

export const isIp = (text: string) => parseIp(text) !== undefined;

/** Whether `ip` lies inside `cidr`. A bare address counts as a /32 or /128. Malformed input matches nothing. */
export const cidrContains = (cidr: string, ip: string): boolean => {
  const [base, prefixText] = cidr.trim().split("/");
  const network = parseIp(base ?? "");
  const address = parseIp(ip);

  if (!network || !address || network.version !== address.version) return false;

  const bits = network.version === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? bits : Number(prefixText);

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return false;

  const shift = BigInt(bits - prefix);

  return network.value >> shift === address.value >> shift;
};

/** In `cidr` and in none of `except`, as NetworkPolicy ipBlocks and Cilium CIDR sets read. */
export const inBlock = (cidr: string, except: readonly string[] | null | undefined, ip: string) =>
  cidrContains(cidr, ip) && !(except ?? []).some((excluded) => cidrContains(excluded, ip));

const privateRanges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "127.0.0.0/8", "::1/128"];

export const isPrivateIp = (ip: string) => privateRanges.some((range) => cidrContains(range, ip));
