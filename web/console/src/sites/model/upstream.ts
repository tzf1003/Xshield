/**
 * Client-side mirror of `xshield_core::site::upstream`: the destination policy the control
 * plane applies to a site's upstream address. It exists to tell the operator, while typing,
 * what the server will refuse and why. The server stays the authority: it classifies the
 * parsed numeric address again on every write and on every health probe.
 *
 * Classification is by parsed numeric value, never by text, and IPv4-mapped, NAT64, 6to4 and
 * Teredo forms are refused outright rather than unwrapped (same as the server).
 */
export type UpstreamRefusal =
  | "unspecified"
  | "loopback"
  | "private"
  | "shared_address_space"
  | "link_local"
  | "unique_local"
  | "multicast"
  | "reserved"
  | "documentation"
  | "ipv4_mapped"
  | "translation"
  | "cloud_metadata";

const v4 = (a: number, b: number, c: number, d: number) =>
  ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;

const METADATA_V4 = [
  v4(169, 254, 169, 254),
  v4(168, 63, 129, 16),
  v4(100, 100, 100, 200),
  v4(192, 0, 0, 192),
];

/** `[base, prefix length, category]`; the first matching entry wins (order is the server's). */
const RANGES_V4: readonly (readonly [number, number, UpstreamRefusal])[] = [
  [v4(0, 0, 0, 0), 8, "unspecified"],
  [v4(10, 0, 0, 0), 8, "private"],
  [v4(100, 64, 0, 0), 10, "shared_address_space"],
  [v4(169, 254, 0, 0), 16, "link_local"],
  [v4(172, 16, 0, 0), 12, "private"],
  [v4(192, 0, 0, 0), 24, "reserved"],
  [v4(192, 0, 2, 0), 24, "documentation"],
  [v4(192, 88, 99, 0), 24, "reserved"],
  [v4(192, 168, 0, 0), 16, "private"],
  [v4(198, 18, 0, 0), 15, "reserved"],
  [v4(198, 51, 100, 0), 24, "documentation"],
  [v4(203, 0, 113, 0), 24, "documentation"],
  [v4(224, 0, 0, 0), 4, "multicast"],
  [v4(240, 0, 0, 0), 4, "reserved"],
];

const v6 = (...segments: number[]): bigint =>
  segments.reduce((value, segment) => (value << 16n) | BigInt(segment), 0n);

const METADATA_V6 = [
  v6(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
  v6(0xfe80, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe),
];

const RANGES_V6: readonly (readonly [bigint, number, UpstreamRefusal])[] = [
  [v6(0, 0, 0, 0, 0, 0, 0, 0), 96, "reserved"],
  [v6(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96, "translation"],
  [v6(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48, "translation"],
  [v6(0x100, 0, 0, 0, 0, 0, 0, 0), 64, "reserved"],
  [v6(0x2001, 0, 0, 0, 0, 0, 0, 0), 32, "translation"],
  [v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32, "documentation"],
  [v6(0x2002, 0, 0, 0, 0, 0, 0, 0), 16, "translation"],
  [v6(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20, "documentation"],
  [v6(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7, "unique_local"],
  [v6(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10, "link_local"],
  [v6(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10, "reserved"],
  [v6(0xff00, 0, 0, 0, 0, 0, 0, 0), 8, "multicast"],
];

const ALL_V6 = (1n << 128n) - 1n;
const inV4 = (address: number, base: number, prefix: number) => {
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (address & mask) >>> 0 === (base & mask) >>> 0;
};
const inV6 = (address: bigint, base: bigint, prefix: number) => {
  const mask = (ALL_V6 << BigInt(128 - prefix)) & ALL_V6;
  return (address & mask) === (base & mask);
};

/** Strict dotted quad: four decimal octets without leading zeros (like Rust's `Ipv4Addr`). */
export function parseIpv4(text: string): number | null {
  const match = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.exec(
    text,
  );
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  if (octets.some((octet) => octet > 255)) return null;
  return v4(octets[0] ?? 0, octets[1] ?? 0, octets[2] ?? 0, octets[3] ?? 0);
}

/** An IPv6 literal (compressed forms and an IPv4 tail allowed) as a 128-bit value. */
export function parseIpv6(text: string): bigint | null {
  if (text.includes("%") || !/^[0-9A-Fa-f:.]+$/.test(text) || !text.includes(":")) return null;
  let head = text;
  if (text.includes(".")) {
    const split = text.lastIndexOf(":");
    const tail = parseIpv4(text.slice(split + 1));
    if (tail === null) return null;
    head = `${text.slice(0, split + 1)}${(tail >>> 16).toString(16)}:${(tail & 0xffff).toString(16)}`;
  }
  const parts = head.split("::");
  if (parts.length > 2) return null;
  const groupsOf = (part: string | undefined) => (part ? part.split(":") : []);
  const left = groupsOf(parts[0]);
  const right = parts.length === 2 ? groupsOf(parts[1]) : [];
  if (parts.length === 1 ? left.length !== 8 : left.length + right.length > 7) return null;
  const groups = [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right];
  if (!groups.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group))) return null;
  return groups.reduce((value, group) => (value << 16n) | BigInt(Number.parseInt(group, 16)), 0n);
}

export type UpstreamSocket =
  | { family: 4; ip: number; host: string; port: number }
  | { family: 6; ip: bigint; host: string; port: number };

/** `ipv4:port` or `[ipv6]:port` with a non-zero port; names and zone identifiers are rejected. */
export function parseUpstreamSocket(address: string): UpstreamSocket | null {
  const bracket = /^\[([^\]]+)\]:(\d{1,5})$/.exec(address);
  const plain = /^([^:[\]]+):(\d{1,5})$/.exec(address);
  const host = bracket?.[1] ?? plain?.[1];
  const port = Number(bracket?.[2] ?? plain?.[2]);
  if (host === undefined || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (bracket) {
    const ip = parseIpv6(host);
    return ip === null ? null : { family: 6, ip, host, port };
  }
  const ip = parseIpv4(host);
  return ip === null ? null : { family: 4, ip, host, port };
}

function refuseV4(address: number): UpstreamRefusal | null {
  if (METADATA_V4.includes(address)) return "cloud_metadata";
  if (inV4(address, v4(127, 0, 0, 0), 8)) return "loopback";
  return RANGES_V4.find(([base, prefix]) => inV4(address, base, prefix))?.[2] ?? null;
}

function refuseV6(address: bigint): UpstreamRefusal | null {
  if (address >> 32n === 0xffffn) return "ipv4_mapped";
  if (METADATA_V6.includes(address)) return "cloud_metadata";
  if (address === 0n) return "unspecified";
  if (address === 1n) return "loopback";
  return RANGES_V6.find(([base, prefix]) => inV6(address, base, prefix))?.[2] ?? null;
}

/** `null` only for a destination that is acceptable as a public upstream. */
export function refuseUpstream(socket: UpstreamSocket): UpstreamRefusal | null {
  return socket.family === 4 ? refuseV4(socket.ip) : refuseV6(socket.ip);
}

export const refusalText: Record<UpstreamRefusal, string> = {
  unspecified: "“本机/本网络”地址（0.0.0.0、::）不能作为上游",
  loopback: "回环地址只在部署方显式开启本地靶场放行时才被接受；生产环境会被拒绝",
  private: "内网地址（RFC 1918）不能作为上游",
  shared_address_space: "运营商级 NAT 共享地址（RFC 6598）不能作为上游",
  link_local: "链路本地地址不能作为上游",
  unique_local: "唯一本地 IPv6 地址（fc00::/7）不能作为上游",
  multicast: "组播地址不能作为上游",
  reserved: "保留、基准测试或不可路由地址不能作为上游",
  documentation: "文档示例网段（RFC 5737/3849）不可路由，服务端会拒绝",
  ipv4_mapped: "IPv4 映射的 IPv6 写法（::ffff:a.b.c.d）一律被拒绝，请直接写 IPv4 地址",
  translation: "NAT64、6to4、Teredo 等内嵌 IPv4 的转换地址一律被拒绝",
  cloud_metadata: "云平台元数据地址不能作为上游",
};

export type UpstreamVerdict = Readonly<{
  /** `warning` never blocks: the server may still accept it (a lab opt-in for loopback). */
  severity: "ok" | "warning" | "error";
  message: string | null;
  refusal: UpstreamRefusal | null;
}>;

const FORMAT_HELP =
  "必须是 IP 字面量加端口，例如 8.8.8.8:443；IPv6 写作 [2001:4860:4860::8888]:443。控制面不会解析域名。";

export function checkUpstreamAddress(address: string): UpstreamVerdict {
  if (address === "") {
    return { severity: "error", message: "请填写源站地址（IP:端口）。", refusal: null };
  }
  const socket = parseUpstreamSocket(address);
  if (socket === null) {
    const looksLikeName = /^[A-Za-z][A-Za-z0-9.-]*(:\d*)?$/.test(address);
    return {
      severity: "error",
      message: looksLikeName ? `不能填域名。${FORMAT_HELP}` : FORMAT_HELP,
      refusal: null,
    };
  }
  const refusal = refuseUpstream(socket);
  if (refusal === null) return { severity: "ok", message: null, refusal: null };
  return {
    severity: refusal === "loopback" ? "warning" : "error",
    message: refusalText[refusal],
    refusal,
  };
}

const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/** The server name is SNI and Host: it must be a DNS name, never something that reads as an IP. */
export function checkServerName(name: string): string | null {
  if (name === "") return "请填写源站服务名（域名，用作 SNI 与 Host）。";
  if (name.length > 253 || !name.split(".").every((label) => LABEL.test(label))) {
    return "服务名必须是合法域名：只含字母、数字和连字符，每段不超过 63 个字符。";
  }
  const last = name.split(".").at(-1) ?? "";
  // The URL parser reads a name whose last label is numeric (2130706433, 127.1, 0x7f.1) as IPv4.
  if (/^\d+$/.test(last) || /^0[xX][0-9A-Fa-f]*$/.test(last)) {
    return "服务名不能是 IP 地址（包括 2130706433、127.1 这类写法）；它必须是域名。";
  }
  return null;
}
