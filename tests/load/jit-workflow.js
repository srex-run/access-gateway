import http from "k6/http";
import {check, sleep} from "k6";

export const options = {
  vus: Number(__ENV.VUS || 2),
  duration: __ENV.DURATION || "2m",
  thresholds: {
    http_req_failed: ["rate<0.02"],
    http_req_duration: ["p(95)<1000", "p(99)<3000"]
  }
};

if (__ENV.RUN_MUTATING_JIT_LOAD !== "confirmed") throw new Error("RUN_MUTATING_JIT_LOAD=confirmed is required");
const base = (__ENV.BASE_URL || "").replace(/\/$/, "");
if (!base.startsWith("https://")) throw new Error("BASE_URL must be an HTTPS origin");
for (const name of ["APPLICANT_COOKIE", "REGION_ID", "ASSET_ID", "TARGET_PORT", "SOURCE_IP", "TARGET_ACCOUNT"]) {
  if (!__ENV[name]) throw new Error(`${name} is required`);
}

function params(cookie, extra = {}) {
  return {headers: {Cookie: cookie, Origin: base, "Content-Type": "application/json", ...extra}, redirects: 0};
}

export default function () {
  const key = `load-${__VU}-${__ITER}-${Date.now()}-${Math.floor(Math.random() * 1000000)}`;
  const created = http.post(`${base}/api/v1/access-requests`, JSON.stringify({
    region_id: __ENV.REGION_ID,
    asset_id: __ENV.ASSET_ID,
    target_port: Number(__ENV.TARGET_PORT),
    source_ip: __ENV.SOURCE_IP,
    target_account: __ENV.TARGET_ACCOUNT,
    reason: "production request load test",
    ticket_no: __ENV.TICKET_PREFIX ? `${__ENV.TICKET_PREFIX}-${__VU}-${__ITER}` : null,
    ttl_seconds: Number(__ENV.TTL_SECONDS || 300),
    emergency: false
  }), params(__ENV.APPLICANT_COOKIE, {"Idempotency-Key": key}));
  if (!check(created, {"request created": value => value.status === 201})) return;
  const request = created.json();

  const current = http.get(`${base}/api/v1/access-requests/${request.id}`, params(__ENV.APPLICANT_COOKIE));
  check(current, {"request readable": value => value.status === 200 && value.json().id === request.id});
  sleep(0.1);
}
