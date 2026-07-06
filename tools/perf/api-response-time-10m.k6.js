import http from "k6/http";
import { check, sleep } from "k6";

const baseUrl = (__ENV.BASE_URL || "http://localhost:8080").replace(/\/$/, "");
const vus = Number(__ENV.VUS || 50);
const duration = __ENV.DURATION || "1m";
const limit = __ENV.LIMIT || "100";
const sleepSeconds = Number(__ENV.SLEEP_SECONDS || 1);

const defaultStart = new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString();
const defaultEnd = new Date(Date.now() + 60 * 60 * 1000).toISOString();
const startTime = __ENV.START_TIME || defaultStart;
const endTime = __ENV.END_TIME || defaultEnd;

export const options = {
  scenarios: {
    steady_query_load: {
      executor: "constant-vus",
      vus,
      duration,
    },
  },
  thresholds: {
    checks: ["rate==1"],
    http_req_failed: ["rate==0"],
    "http_req_duration{endpoint:flows}": ["p(95)<2000"],
    "http_req_duration{endpoint:top_ports}": ["p(95)<2000"],
    "http_req_duration{endpoint:top_talkers}": ["p(95)<2000"],
  },
};

function queryString(params) {
  return Object.entries(params)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
}

function getJson(endpoint, path) {
  const response = http.get(`${baseUrl}${path}`, { tags: { endpoint } });
  let payload = null;
  try {
    payload = response.json();
  } catch (_) {
    payload = null;
  }

  check(response, {
    [`${endpoint} status is 200`]: (r) => r.status === 200,
    [`${endpoint} returns JSON`]: () => payload !== null,
  });
  check(
    payload,
    {
      [`${endpoint} reports took_ms`]: (body) =>
        body !== null && Number.isFinite(body.took_ms),
      [`${endpoint} server took_ms is below 2000`]: (body) =>
        body !== null && Number.isFinite(body.took_ms) && body.took_ms < 2000,
    },
    { endpoint }
  );
  return payload;
}

export default function () {
  const windowParams = {
    start_time: startTime,
    end_time: endTime,
  };
  const windowQuery = queryString(windowParams);

  const flows = getJson("flows", `/flows?${windowQuery}&limit=${encodeURIComponent(limit)}`);
  check(
    flows,
    {
      "flows response has data": (body) =>
        body !== null && Array.isArray(body.data) && body.data.length > 0,
    },
    { endpoint: "flows" }
  );

  const topPorts = getJson(
    "top_ports",
    `/flows/aggregations/top-ports?${windowQuery}&metric=bytes&limit=10`
  );
  check(
    topPorts,
    {
      "top_ports response has buckets": (body) =>
        body !== null && Array.isArray(body.results) && body.results.length > 0,
    },
    { endpoint: "top_ports" }
  );

  const topTalkers = getJson(
    "top_talkers",
    `/flows/aggregations/top-talkers?${windowQuery}&metric=bytes&limit=10`
  );
  check(
    topTalkers,
    {
      "top_talkers response has buckets": (body) =>
        body !== null && Array.isArray(body.results) && body.results.length > 0,
    },
    { endpoint: "top_talkers" }
  );

  sleep(sleepSeconds);
}
