import { describe, expect, test } from "bun:test";
import { scrubSecretText, scrubSecretValue } from "../src/index.ts";

// Fixture credentials are assembled at runtime so no literal vendor token is ever committed.
const j = (...parts: string[]) => parts.join("");
const JWT = j("ey", "JhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiJzeW50aGV0aWMifQ", ".", "c3ludGhldGljc2ln");
const SLACK_USER = j("xo", "xp-", "1111-2222-synthfixture");
const GH_FINE = j("github", "_pat_", "11SYNTH0000_fixturefixturefixture");
const ES_API_KEY = "c3ludGhldGljOmVzYXBpa2V5Zml4dHVyZQ==";

describe("shared credential scrubber", () => {
  const cases: ReadonlyArray<readonly [string, string, string]> = [
    ["JWT", `token issued ${JWT} to user`, JWT],
    ["Slack user token", `slack=${SLACK_USER}`, SLACK_USER],
    ["GitHub fine-grained PAT", `push with ${GH_FINE} now`, GH_FINE],
    ["password=", "login password=synthPassw0rdValue&next=1", "synthPassw0rdValue"],
    ["access_token query", "GET /cb?access_token=synthAccessTokenValue&x=1", "synthAccessTokenValue"],
    ["client_secret=", "client_secret=synthClientSecretValue", "synthClientSecretValue"],
    ["ES ApiKey header", `Authorization: ApiKey ${ES_API_KEY}`, ES_API_KEY],
    ["ES ApiKey standalone", `used ApiKey ${ES_API_KEY} for _search`, ES_API_KEY],
    ["JSON password", '{"password":"synth pass with spaces"}', "synth pass with spaces"],
    ["JSON api_key", '{"api_key": "synthJsonApiKeyValue"}', "synthJsonApiKeyValue"],
    ["JSON cookie", '{"cookie":"sid=synthCookieValue; theme=dark"}', "synthCookieValue"],
    ["JSON Authorization ApiKey", `{"Authorization":"ApiKey ${ES_API_KEY}"}`, ES_API_KEY],
    ["URL userinfo", "https://elastic:synthP@ss@es.example.internal:9200/_search", "synthP@ss"],
  ];

  for (const [label, input, secret] of cases) {
    test(`redacts ${label}`, () => {
      const out = scrubSecretText(input);
      expect(out).not.toContain(secret);
      expect(out).toContain("[REDACTED");
    });
  }

  test("leaves ordinary hunt telemetry untouched", () => {
    const benign =
      "process.name:powershell.exe host.name:workstation-01 evt-0001 ip.src == 192.0.2.10 " +
      "dns.qry.name:example.test Basic analysis of tokens observed.";
    expect(scrubSecretText(benign)).toBe(benign);
  });

  test("redacts credential-named keys in nested values", () => {
    const out = scrubSecretValue({
      headers: { Authorization: `ApiKey ${ES_API_KEY}`, "X-Api-Key": "synthHeaderKey" },
      nested: [{ client_secret: "synthNestedSecret", note: `see ${SLACK_USER}` }],
      host: "workstation-01",
    });
    const text = JSON.stringify(out);
    for (const s of [ES_API_KEY, "synthHeaderKey", "synthNestedSecret", SLACK_USER]) {
      expect(text).not.toContain(s);
    }
    expect(out.host).toBe("workstation-01");
  });

  test("scrubs adversarial 1 MB inputs in linear time", () => {
    const MB = 1024 * 1024;
    const inputs = [
      "x".repeat(MB),
      "a1".repeat(MB / 2),
      ":".repeat(MB),
      `https://${":".repeat(MB)}`,
      `https://user:${"p".repeat(MB)}`,
      `ey${"J".repeat(MB)}`,
      "password=".repeat(MB / 9),
      '{"password":"'.repeat(MB / 13),
      "Bearer ".repeat(MB / 7),
      "a://".repeat(MB / 4),
    ];
    for (const input of inputs) {
      const started = performance.now();
      scrubSecretText(input);
      expect(performance.now() - started).toBeLessThan(500);
    }
  });
});
