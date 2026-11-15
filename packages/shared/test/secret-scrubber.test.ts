import { describe, expect, test } from "bun:test";
import { scrubSecretText, scrubSecretValue } from "../src/index.ts";

/**
 * Fastest of up to three timed runs, stopping at the first one under budget. A load spike on a
 * busy machine can't fail a linear-time check this way, but a quadratic input is slow on every run.
 */
function fastestMs(run: () => unknown, budgetMs: number): number {
  let best = Number.POSITIVE_INFINITY;
  for (let attempt = 0; attempt < 3 && best >= budgetMs; attempt++) {
    const started = performance.now();
    run();
    best = Math.min(best, performance.now() - started);
  }
  return best;
}

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

  test("redacts credentials in JSON nested inside strings at any depth up to the cap", () => {
    const M = "NESTEDLEAK";
    const inner = JSON.stringify({ user: "a", password: `${M} two words`, access_token: `${M}at` });
    let wrapped = inner;
    const shapes: unknown[] = [];
    // 1..MAX levels of JSON-in-a-string, plus JSON strings inside arrays.
    for (let level = 1; level <= 8; level++) {
      shapes.push({ message: wrapped });
      wrapped = JSON.stringify({ body: wrapped });
    }
    shapes.push({ hits: [[inner]] }, [JSON.stringify([inner])]);
    for (const shape of shapes) {
      expect(JSON.stringify(scrubSecretValue(shape))).not.toContain(M);
    }
    // Non-credential content in an embedded document survives.
    const out = scrubSecretValue({ message: JSON.stringify({ body: JSON.stringify({ host: "workstation-01", password: "x" }) }) });
    expect(JSON.parse(JSON.parse(out.message).body)).toEqual({ host: "workstation-01", password: "[REDACTED_SECRET]" });
  });

  test("redacts credential-named keys whatever the value type", () => {
    const M = "TYPEDLEAK";
    const out = JSON.stringify(
      scrubSecretValue({
        password: [`${M}hunter2`],
        client_secret: { value: `${M}cs` },
        token: [`${M}123456`],
        api_key: 1234567890123,
        empty: { password: "" },
      }),
    );
    expect(out).not.toContain(M);
    expect(out).not.toContain("1234567890123");
    expect(JSON.parse(out).password).toBe("[REDACTED_SECRET]");
    expect(JSON.parse(out).empty).toEqual({ password: "" });
  });

  test("text that only looks like JSON is still scrubbed as text, and deep nesting stays linear", () => {
    expect(scrubSecretValue("{not json password=synthTextPass}")).not.toContain("synthTextPass");
    const deep = "[".repeat(200_000) + "]".repeat(200_000);
    let big = JSON.stringify({ password: "x", filler: "y".repeat(1024 * 1024) });
    for (let i = 0; i < 8; i++) big = JSON.stringify({ body: big });
    const ms = fastestMs(() => {
      scrubSecretValue({ message: deep });
      scrubSecretValue({ message: big });
    }, 3_000);
    expect(ms).toBeLessThan(3_000);
  });

  test("redacts escaped JSON pairs after a text prefix, at any escape depth", () => {
    const L = "ESCLEAK";
    const cases = [
      `log: {"body":"{\\"password\\":\\"${L} two words\\"}"}`,
      `msg=accepted {\\"api_key\\":\\"${L}y\\"} done`,
      `deep {\\\\\\"token\\\\\\":\\\\\\"${L}zz\\\\\\"}`,
      // A deeper-escaped quote inside the value does not end it early.
      `x {\\"password\\":\\"in \\\\\\"q\\\\\\" ${L}tail\\"} y`,
      `{"password":"a\\"${L}b"}`,
    ];
    for (const input of cases) {
      const out = scrubSecretText(input);
      expect(out, input).not.toContain(L);
      expect(out).toContain("[REDACTED_SECRET]");
    }
    // The text around the pair survives, including the closing escaped quote.
    expect(scrubSecretText(`msg=ok {\\"api_key\\":\\"${L}\\",\\"user\\":\\"alice\\"} end`)).toBe(
      `msg=ok {\\"api_key\\":\\"[REDACTED_SECRET]\\",\\"user\\":\\"alice\\"} end`,
    );
  });

  test("redacts env-style credential names", () => {
    const L = "ENVLEAK";
    const cases = [
      `DB_PASSWORD=${L}hunter2`,
      `AWS_SECRET_ACCESS_KEY=${L}abc123`,
      `GITHUB_TOKEN=${L}abc123`,
      `MY_API_KEY: ${L}abc123`,
      `export FOO_SECRET=${L}abc123`,
      `env: {"SERVICE_PASSWORD": "${L}x"}`,
    ];
    for (const input of cases) {
      expect(scrubSecretText(input), input).not.toContain(L);
    }
    for (const benign of ["input_tokens: 1200", "token_count: 5", "AWS_ACCESS_KEY_ID=AKID-not-secret", "secrets_manager_arn=arn"]) {
      expect(scrubSecretText(benign)).toBe(benign);
    }
  });

  test("is idempotent: scrubbing scrubbed text changes nothing", () => {
    const once = scrubSecretText(cases.map(([, input]) => input).join("\n") + "\nCookie: a=b\nX-Api-Key: synthKey");
    expect(scrubSecretText(once)).toBe(once);
    const header = "Authorization:" + " ".repeat(1024 * 1024);
    expect(fastestMs(() => scrubSecretText(header), 3_000)).toBeLessThan(3_000);
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
      `${"\\".repeat(MB)}"password":"x"`,
      `"password":"${"\\".repeat(MB)}`,
      `\\"password\\":\\"${"x\\\\\\\"".repeat(MB / 5)}`,
      `${"A_".repeat(MB / 2)}PASSWORX=`,
    ];
    for (const input of inputs) {
      expect(fastestMs(() => scrubSecretText(input), 3_000)).toBeLessThan(3_000);
    }
  }, 60_000);

  test("stays linear on repeated escaped-JSON and env-style key shapes", () => {
    const MB = 1024 * 1024;
    const prefixes = [
      // Escaped JSON pairs at several escape depths, and env-style prefixed keys.
      '\\"password\\":\\"', '\\\\\\"password\\\\\\":\\\\\\"', '"password":"x\\"', '\\"password\\":\\"x\\\\\\"',
      "\\", "\\\\\\\\\\\\\\\\", '\\"', '\\\\\\"', "DB_PASSWORD=", "A_", "a_b_",
    ];
    for (const prefix of prefixes) {
      for (const sep of ["", " ", ":", "=", "a"]) {
        const unit = prefix + sep;
        const input = unit.repeat(Math.ceil(MB / unit.length));
        const ms = fastestMs(() => scrubSecretText(input), 3_000);
        expect(ms, `${JSON.stringify(unit)} x ${input.length} took ${Math.round(ms)}ms`).toBeLessThan(3_000);
      }
    }
  }, 60_000);

  test("stays linear when any token prefix repeats with any separator", () => {
    const MB = 1024 * 1024;
    const prefixes = [
      j("ey", "J"), j("ey", "Jabcd."), j("s", "k-"), j("s", "k-ant-"), j("xo", "xb-"), j("xa", "pp-"),
      j("github", "_pat_"), j("gh", "p_"), j("gl", "pat-"), j("AK", "IA"), j("AI", "za"),
      "Bearer ", "ApiKey ", "password", "token", "https://u:", '"password":"', "Authorization:",
    ];
    for (const prefix of prefixes) {
      for (const sep of ["", "-", "_", ".", " ", ":", "=", "a"]) {
        const unit = prefix + sep;
        const input = unit.repeat(Math.ceil(MB / unit.length));
        const ms = fastestMs(() => scrubSecretText(input), 3_000);
        expect(ms, `${JSON.stringify(unit)} x ${input.length} took ${Math.round(ms)}ms`).toBeLessThan(3_000);
      }
    }
  }, 120_000);
});
