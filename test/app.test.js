import assert from "node:assert/strict";
import test from "node:test";

import worker, {
  TARGETS,
  buildPlaceholderRegions,
  buildRegionGroups,
  getTargetConfig,
  getStatus,
  parseDescribeInstancesXml,
  performAction,
  refreshTargets,
} from "../src/index.js";

const TWO_US_WEST_TARGETS = [
  { region: "us-west-2", instanceId: "i-1", name: "SEA-1" },
  { region: "us-west-2", instanceId: "i-2", name: "SEA-2" },
];

function makeEnv(overrides = {}) {
  return {
    APP_PASSWORD: "secret-pass",
    SESSION_SECRET: "session-secret",
    AWS_REGION: "us-west-2",
    EC2_INSTANCE_ID: "i-123",
    AWS_ACCESS_KEY_ID: "key",
    AWS_SECRET_ACCESS_KEY: "secret",
    ...overrides,
  };
}

test("GET / shows login page when not authenticated", async () => {
  const response = await worker.fetch(new Request("https://example.com/"), makeEnv());
  const text = await response.text();

  assert.equal(response.status, 200);
  assert.match(text, /請輸入密碼/);
  assert.match(text, /Microsoft YaHei/);
});

test("POST /login with valid password sets a session cookie", async () => {
  const body = new URLSearchParams({ password: "secret-pass" });
  const response = await worker.fetch(
    new Request("https://example.com/login", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
    }),
    makeEnv(),
  );

  assert.equal(response.status, 302);
  assert.match(response.headers.get("set-cookie") || "", /ec2_session=/);
});

test("POST /login rate limits repeated failed attempts by IP", async () => {
  const loginFailures = new Map();
  const env = makeEnv({
    __testHooks: {
      loginFailures,
      now: () => 1_700_000_000_000,
    },
  });

  for (let index = 0; index < 5; index += 1) {
    const response = await worker.fetch(
      new Request("https://example.com/login", {
        method: "POST",
        headers: {
          "cf-connecting-ip": "203.0.113.10",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ password: "wrong-pass" }),
      }),
      env,
    );
    assert.equal(response.status, 401);
  }

  const blocked = await worker.fetch(
    new Request("https://example.com/login", {
      method: "POST",
      headers: {
        "cf-connecting-ip": "203.0.113.10",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ password: "secret-pass" }),
    }),
    env,
  );

  assert.equal(blocked.status, 429);
});

test("GET /api/status rejects requests without a session", async () => {
  const response = await worker.fetch(
    new Request("https://example.com/api/status"),
    makeEnv(),
  );

  assert.equal(response.status, 401);
});

test("parseDescribeInstancesXml extracts state and public DNS name", () => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
  <DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    <reservationSet>
      <item>
        <instancesSet>
          <item>
            <instanceId>i-123</instanceId>
            <dnsName>ec2-155-146-132-179.us-west-2.compute.amazonaws.com</dnsName>
            <instanceState>
              <name>running</name>
            </instanceState>
          </item>
        </instancesSet>
      </item>
    </reservationSet>
  </DescribeInstancesResponse>`;

  const result = parseDescribeInstancesXml(xml);

  assert.deepEqual(result, {
    instanceId: "i-123",
    state: "running",
    publicDnsName: "ec2-155-146-132-179.us-west-2.compute.amazonaws.com",
    awsNameTag: "",
  });
});

test("GET /api/status returns instance state and DNS when authenticated", async () => {
  const response = await worker.fetch(
    new Request("https://example.com/api/status", {
      headers: {
        cookie: "ec2_session=" + encodeURIComponent("signed:secret-pass"),
      },
    }),
    makeEnv({
      __testHooks: {
        verifySession: () => true,
        getStatus: async () => ({
          instanceId: "i-123",
          state: "running",
          publicDnsName: "ec2-155-146-132-179.us-west-2.compute.amazonaws.com",
        }),
      },
    }),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    instanceId: "i-123",
    state: "running",
    publicDnsName: "ec2-155-146-132-179.us-west-2.compute.amazonaws.com",
  });
});

test("getStatus sends DescribeInstances and parses the XML response", async () => {
  let fetchCall = null;
  const env = makeEnv({
    __testHooks: {
      fetch: async (url, init) => {
        fetchCall = { url, init };
        return new Response(
          `<?xml version="1.0" encoding="UTF-8"?>
          <DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
            <reservationSet>
              <item>
                <instancesSet>
                  <item>
                    <instanceId>i-123</instanceId>
                    <dnsName>ec2-155-146-132-179.us-west-2.compute.amazonaws.com</dnsName>
                    <instanceState><name>running</name></instanceState>
                  </item>
                </instancesSet>
              </item>
            </reservationSet>
          </DescribeInstancesResponse>`,
          { status: 200, headers: { "content-type": "application/xml" } },
        );
      },
    },
  });

  const result = await getStatus(env);

  assert.equal(fetchCall.url, "https://ec2.us-west-2.amazonaws.com/");
  assert.match(String(fetchCall.init.body), /Action=DescribeInstances/);
  assert.match(String(fetchCall.init.body), /InstanceId\.1=i-0d50f2b47b60208cb/);
  assert.deepEqual(result, {
    instanceId: "i-123",
    state: "running",
    publicDnsName: "ec2-155-146-132-179.us-west-2.compute.amazonaws.com",
    awsNameTag: "",
  });
});

test("performAction rejects restart", async () => {
  const env = makeEnv({
    __testHooks: {
      fetch: async () => {
        throw new Error("fetch should not be called");
      },
    },
  });

  await assert.rejects(
    () => performAction(env, "restart"),
    /Unsupported action: restart/,
  );
});

test("getTargetConfig falls back to built-in region and instance id", () => {
  const result = getTargetConfig({});

  assert.deepEqual(result, {
    region: "us-west-2",
    instanceId: "i-0d50f2b47b60208cb",
  });
});

test("getTargetConfig uses the first configured target instead of EC2 env vars", () => {
  const result = getTargetConfig({
    AWS_REGION: "ap-northeast-1",
    EC2_INSTANCE_ID: "i-env-only",
  });

  assert.deepEqual(result, {
    region: "us-west-2",
    instanceId: "i-0d50f2b47b60208cb",
  });
});

test("buildRegionGroups groups configured targets by region", () => {
  const groups = buildRegionGroups(TARGETS);

  assert.deepEqual(groups.map((group) => group.region), ["us-west-2"]);
  assert.equal(groups[0].items.length, 1);
});

test("buildPlaceholderRegions creates per-region placeholders before refresh", () => {
  const regions = buildPlaceholderRegions(TARGETS);
  const firstUsWest = regions.find((region) => region.region === "us-west-2").items[0];

  assert.equal(firstUsWest.state, "未刷新");
  assert.equal(firstUsWest.publicDnsName, "未刷新");
  assert.equal(firstUsWest.region, "us-west-2");
});

test("GET / renders grouped placeholder machines without AWS refresh", async () => {
  const response = await worker.fetch(
    new Request("https://example.com/", {
      headers: {
        cookie: "ec2_session=" + encodeURIComponent("signed:secret-pass"),
      },
    }),
    makeEnv({
      __testHooks: {
        verifySession: () => true,
      },
    }),
  );
  const text = await response.text();

  assert.equal(response.status, 200);
  assert.match(text, /未刷新/);
  assert.match(text, /us-west-2/);
  assert.doesNotMatch(text, /重新啟動/);
  assert.doesNotMatch(text, /data-action="restart"/);
});

test("POST /api/action rejects unknown targets", async () => {
  const response = await worker.fetch(
    new Request("https://example.com/api/action", {
      method: "POST",
      headers: {
        cookie: "ec2_session=" + encodeURIComponent("signed:secret-pass"),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        region: "us-west-2",
        instanceId: "i-does-not-exist",
        action: "stop",
      }),
    }),
    makeEnv({
      __testHooks: {
        verifySession: () => true,
      },
    }),
  );

  assert.equal(response.status, 400);
});

test("POST /api/action rejects restart", async () => {
  const response = await worker.fetch(
    new Request("https://example.com/api/action", {
      method: "POST",
      headers: {
        cookie: "ec2_session=" + encodeURIComponent("signed:secret-pass"),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        region: "us-west-2",
        instanceId: "i-0d50f2b47b60208cb",
        action: "restart",
      }),
    }),
    makeEnv({
      __testHooks: {
        verifySession: () => true,
      },
    }),
  );

  assert.equal(response.status, 400);
});

test("POST /api/refresh batches DescribeInstances by region", async () => {
  const calls = [];
  const response = await worker.fetch(
    new Request("https://example.com/api/refresh", {
      method: "POST",
      headers: {
        cookie: "ec2_session=" + encodeURIComponent("signed:secret-pass"),
      },
    }),
    makeEnv({
      __testHooks: {
        verifySession: () => true,
        fetch: async (url, init) => {
          calls.push({ url, init });
          const body = String(init.body);
          const instanceIdMatch = body.match(/InstanceId\.1=([^&]+)/);
          const instanceId = decodeURIComponent(instanceIdMatch?.[1] || "i-unknown");
          return new Response(
            `<?xml version="1.0" encoding="UTF-8"?>
            <DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
              <reservationSet>
                <item>
                  <instancesSet>
                    <item>
                      <instanceId>${instanceId}</instanceId>
                      <dnsName>${instanceId}.example.internal</dnsName>
                      <instanceState><name>running</name></instanceState>
                    </item>
                  </instancesSet>
                </item>
              </reservationSet>
            </DescribeInstancesResponse>`,
            { status: 200, headers: { "content-type": "application/xml" } },
          );
        },
      },
    }),
  );

  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(payload.regions.length, 1);
  assert.match(String(calls[0].init.body), /Action=DescribeInstances/);
});

test("refreshTargets maps multiple instances returned in one region", async () => {
  const payload = await refreshTargets(
    makeEnv({
      __testHooks: {
        fetch: async () =>
          new Response(
            `<?xml version="1.0" encoding="UTF-8"?>
            <DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
              <reservationSet>
                <item>
                  <instancesSet>
                    <item>
                      <instanceId>i-1</instanceId>
                      <dnsName>i-1.example.internal</dnsName>
                      <instanceState><name>running</name></instanceState>
                    </item>
                    <item>
                      <instanceId>i-2</instanceId>
                      <dnsName>i-2.example.internal</dnsName>
                      <instanceState><name>stopped</name></instanceState>
                    </item>
                  </instancesSet>
                </item>
              </reservationSet>
            </DescribeInstancesResponse>`,
            { status: 200, headers: { "content-type": "application/xml" } },
          ),
      },
    }),
    TWO_US_WEST_TARGETS,
  );

  assert.deepEqual(
    payload.regions[0].items.map((item) => ({
      instanceId: item.instanceId,
      state: item.state,
      publicDnsName: item.publicDnsName,
    })),
    [
      {
        instanceId: "i-1",
        state: "running",
        publicDnsName: "i-1.example.internal",
      },
      {
        instanceId: "i-2",
        state: "stopped",
        publicDnsName: "i-2.example.internal",
      },
    ],
  );
});

test("POST /api/action sends the selected target to AWS", async () => {
  let fetchCall = null;
  const response = await worker.fetch(
    new Request("https://example.com/api/action", {
      method: "POST",
      headers: {
        cookie: "ec2_session=" + encodeURIComponent("signed:secret-pass"),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        region: "us-west-2",
        instanceId: "i-0d50f2b47b60208cb",
        action: "stop",
      }),
    }),
    makeEnv({
      __testHooks: {
        verifySession: () => true,
        fetch: async (url, init) => {
          fetchCall = { url, init };
          return new Response("<ok />", { status: 200 });
        },
      },
    }),
  );

  assert.equal(response.status, 200);
  assert.equal(fetchCall.url, "https://ec2.us-west-2.amazonaws.com/");
  assert.match(String(fetchCall.init.body), /Action=StopInstances/);
  assert.match(String(fetchCall.init.body), /InstanceId\.1=i-0d50f2b47b60208cb/);
});
