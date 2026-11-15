/**
 * Canonical Hunt Lab field allowlists, defaults, and filter constants
 * mirrored 1-for-1 from hermes-hunt-bots framework/hunt_lab/guest/lab_server.py (ADR-0003).
 */

export const EVENT_FIELDS = [
  "@timestamp",
  "ecs",
  "event",
  "host",
  "user",
  "group",
  "process",
  "file",
  "service",
  "source",
  "destination",
  "network",
  "dns",
  "url",
  "http",
  "tls",
  "user_agent",
  "observer",
  "winlog",
  "powershell",
  "message",
  "labels",
] as const;

export type EventTopLevelField = (typeof EVENT_FIELDS)[number];

export const NETWORK_FIELDS = [
  "firstPacket",
  "lastPacket",
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "network.packets",
  "network.bytes",
  "network.protocol",
  "dns.host",
  "node",
] as const;

export type NetworkSummaryField = (typeof NETWORK_FIELDS)[number];

export const KEYWORD_FIELDS = [
  "event.id",
  "event.dataset",
  "event.kind",
  "event.category",
  "event.type",
  "event.action",
  "event.outcome",
  "event.code",
  "event.provider",
  "host.name",
  "host.ip",
  "user.name",
  "user.domain",
  "process.entity_id",
  "process.pid",
  "process.name",
  "process.executable",
  "process.command_line",
  "process.parent.entity_id",
  "process.parent.pid",
  "process.parent.name",
  "process.parent.executable",
  "process.parent.command_line",
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "network.protocol",
  "network.transport",
  "network.direction",
  "network.type",
  "dns.question.name",
  "dns.question.type",
  "dns.answers.data",
  "url.domain",
  "url.full",
  "http.request.method",
  "http.response.status_code",
  "tls.server_name",
  "file.path",
  "file.name",
  "winlog.channel",
  "user_agent.original",
  // Scenario generator fields (both stories)
  "dns.response_code",
  "group.name",
  "host.os.name",
  "host.os.type",
  "http.request.bytes",
  "http.response.bytes",
  "observer.name",
  "observer.type",
  "process.hash.sha256",
  "service.name",
  "url.path",
  "url.query",
  "url.scheme",
  "user.target.domain",
  "user.target.name",
  "winlog.event_data.AccountName",
  "winlog.event_data.AuthenticationPackageName",
  "winlog.event_data.FailureReason",
  "winlog.event_data.GrantedAccess",
  "winlog.event_data.ImagePath",
  "winlog.event_data.LogonProcessName",
  "winlog.event_data.LogonType",
  "winlog.event_data.MemberName",
  "winlog.event_data.PrivilegeList",
  "winlog.event_data.ServiceName",
  "winlog.event_data.ServiceType",
  "winlog.event_data.StartType",
  "winlog.event_data.Status",
  "winlog.event_data.SubStatus",
  "winlog.event_data.SubjectLogonId",
  "winlog.event_data.SubjectUserName",
  "winlog.event_data.TargetDomainName",
  "winlog.event_data.TargetImage",
  "winlog.event_data.TargetLogonId",
  "winlog.event_data.TargetProcessGuid",
  "winlog.event_data.TargetProcessId",
  "winlog.event_data.TargetUserName",
  "winlog.event_data.TaskContent",
  "winlog.event_data.TaskName",
  "winlog.event_data.WorkstationName",
  // Real winlogbeat/Sysmon/PowerShell fields (Sysmon spells TargetProcessGUID)
  "event.module",
  "process.args",
  "process.title",
  "process.hash.md5",
  "process.hash.sha1",
  "file.directory",
  "file.extension",
  "winlog.record_id",
  "winlog.event_id",
  "winlog.computer_name",
  "winlog.provider_name",
  "winlog.task",
  "winlog.process.pid",
  "winlog.event_data.User",
  "winlog.event_data.IntegrityLevel",
  "winlog.event_data.LogonId",
  "winlog.event_data.ParentUser",
  "winlog.event_data.OriginalFileName",
  "winlog.event_data.Description",
  "winlog.event_data.Company",
  "winlog.event_data.Product",
  "winlog.event_data.Signed",
  "winlog.event_data.Signature",
  "winlog.event_data.SignatureStatus",
  "winlog.event_data.RuleName",
  "winlog.event_data.CreationUtcTime",
  "winlog.event_data.EventType",
  "winlog.event_data.SourceUser",
  "winlog.event_data.TargetUser",
  "winlog.event_data.TargetProcessGUID",
] as const;

export type KeywordField = (typeof KEYWORD_FIELDS)[number];

export const AGG_FIELDS: ReadonlySet<string> = new Set<string>(KEYWORD_FIELDS);
export const ES_AGG_FIELDS = KEYWORD_FIELDS;

export const SEARCH_EXTRA_FIELDS = [
  "@timestamp",
  "message",
  "dns.answers",
  "network.bytes",
  "network.packets",
  "powershell.file.script_block_text",
] as const;

export const ES_RETURN_FIELDS = [...KEYWORD_FIELDS, ...SEARCH_EXTRA_FIELDS] as const;
export type SearchField = (typeof ES_RETURN_FIELDS)[number];

export const SEARCH_FIELDS: ReadonlySet<string> = new Set<string>(ES_RETURN_FIELDS);

export const LABEL_FIELD_RE = /^labels\.[a-z0-9_]{1,40}$/;

export function isAllowedSearchField(field: string): boolean {
  return SEARCH_FIELDS.has(field) || LABEL_FIELD_RE.test(field);
}

export function isAllowedAggField(field: string): boolean {
  return AGG_FIELDS.has(field);
}

export const ALWAYS_FIELDS = ["event.id", "@timestamp", "host.name"] as const;

export const DEFAULT_FIELDS = [
  ...ALWAYS_FIELDS,
  "event.category",
  "event.action",
  "user.name",
  "process.name",
  "process.command_line",
  "source.ip",
  "destination.ip",
  "destination.port",
  "dns.question.name",
  "url.domain",
  "message",
] as const;

export const QUERY_FIELDS = [
  "message",
  "event.id",
  "event.action",
  "host.name",
  "user.name",
  "process.name",
  "process.parent.name",
  "process.command_line.text",
  "process.parent.command_line.text",
  "dns.question.name",
  "url.domain",
  "url.full.text",
  "tls.server_name",
  "file.path.text",
] as const;

/**
 * A `*`/`?` that starts a term: at the start, after a delimiter, or after a prefix operator
 * (`+`, `!`, `-`) that itself starts the term. A `-` inside a term (`workstation-*`) is not one.
 */
export const LEADING_WILDCARD_RE = /(?:^|[\s(\[{:,"])[+!-]?[*?]/;

export const INTERVALS = {
  "1m": 60,
  "5m": 300,
  "15m": 900,
  "1h": 3600,
} as const;

export type HistogramInterval = keyof typeof INTERVALS;

export const INTEL_FIELDS = [
  "id",
  "indicator.type",
  "indicator.value",
  "threat.feed.name",
  "confidence",
  "description",
  "first_seen",
] as const;

export type IntelField = (typeof INTEL_FIELDS)[number];

export const ARKIME_SESSION_FIELDS = [
  "firstPacket",
  "lastPacket",
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "ipProtocol",
  "protocol",
  "network.bytes",
  "network.packets",
  "source.bytes",
  "destination.bytes",
  "dns.host",
  "dns.qt",
  "http.host",
  "http.uri",
  "http.method",
  "http.statuscode",
  "http.useragent",
  "tls.version",
  "tls.cipher",
  "tls.ja3",
  "tls.ja4",
  "tags",
] as const;

export type ArkimeSessionField = (typeof ARKIME_SESSION_FIELDS)[number];

export const ARKIME_DEFAULT_FIELDS = [
  "firstPacket",
  "lastPacket",
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "ipProtocol",
  "protocol",
  "network.bytes",
  "network.packets",
  "dns.host",
  "http.host",
] as const;

export const ARKIME_UNIQUE_FIELD_LIST = [
  "ip.src",
  "ip.dst",
  "port.src",
  "port.dst",
  "ip.protocol",
  "protocols",
  "host.dns",
  "host.http",
  "http.uri",
  "http.method",
  "http.statuscode",
  "http.user-agent",
  "dns.query.type",
  "tls.version",
  "tls.cipher",
  "tls.ja3",
  "tls.ja4",
  "tags",
] as const;

export type ArkimeUniqueField = (typeof ARKIME_UNIQUE_FIELD_LIST)[number];
export const ARKIME_UNIQUE_FIELDS: ReadonlySet<string> = new Set<string>(ARKIME_UNIQUE_FIELD_LIST);

export const PACKET_ALWAYS_FIELDS = ["frame.number", "frame.time_epoch"] as const;

export const PACKET_FIELDS = [
  "frame.number",
  "frame.time_epoch",
  "frame.len",
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "tcp.srcport",
  "tcp.dstport",
  "tcp.stream",
  "udp.srcport",
  "udp.dstport",
  "_ws.col.Protocol",
  "dns.qry.name",
  "dns.qry.type",
  "dns.flags.rcode",
  "dns.a",
  "dns.aaaa",
  "dns.cname",
  "http.host",
  "http.request.method",
  "http.request.uri",
  "http.response.code",
  "http.user_agent",
  "http.content_type",
  "http.content_length",
  "tls.handshake.type",
  "tls.handshake.extensions_server_name",
  "tls.handshake.ja3",
  "tls.handshake.ja3s",
  "tls.handshake.ja4",
  "tls.record.version",
  "smb2.cmd",
  "smb2.filename",
  "smb2.tree",
  "kerberos.CNameString",
  "ntlmssp.auth.username",
  "ntlmssp.auth.domain",
] as const;

export type AllowedPacketField = (typeof PACKET_FIELDS)[number];
export const ADR0003_PACKET_FIELD_ALLOWLIST = PACKET_FIELDS;

export const PACKET_DEFAULT_FIELDS = [
  "ip.src",
  "ip.dst",
  "tcp.dstport",
  "udp.dstport",
  "_ws.col.Protocol",
  "dns.qry.name",
  "http.host",
  "tls.handshake.extensions_server_name",
] as const;

export const PACKET_COLUMN_FIELDS: ReadonlySet<string> = new Set<string>(["_ws.col.Protocol"]);

export const PACKET_FILTER_FIELD_LIST = PACKET_FIELDS.filter(
  (field): field is Exclude<AllowedPacketField, "_ws.col.Protocol" | "http.request.uri"> =>
    field !== "_ws.col.Protocol" && field !== "http.request.uri",
);

export const PACKET_FILTER_FIELDS: ReadonlySet<string> = new Set<string>(PACKET_FILTER_FIELD_LIST);

export const PACKET_FILTER_PROTOCOLS = [
  "ip",
  "ipv6",
  "tcp",
  "udp",
  "dns",
  "http",
  "tls",
  "smb2",
  "kerberos",
  "ntlmssp",
  "arp",
  "icmp",
] as const;

export type PacketFilterProtocol = (typeof PACKET_FILTER_PROTOCOLS)[number];

export const PACKET_FILTER_WORDS = {
  and: "logic",
  or: "logic",
  not: "not",
  eq: "compare",
  ne: "compare",
  gt: "compare",
  lt: "compare",
  ge: "compare",
  le: "compare",
} as const;

export const PACKET_FILTER_OPERATORS = {
  "==": "compare",
  "!=": "compare",
  ">=": "compare",
  "<=": "compare",
  ">": "compare",
  "<": "compare",
  "&&": "logic",
  "||": "logic",
  "!": "not",
  "(": "open",
  ")": "close",
} as const;

export const MAX_PACKET_FILTER = 300;
export const MAX_PACKET_FILTER_DEPTH = 20;
export const MAX_PACKET_START = 100_000;
export const MAX_PACKET_VALUE = 1_000;
export const PACKET_FIELDS_REDACTED_QUERY = "?[redacted]" as const;
