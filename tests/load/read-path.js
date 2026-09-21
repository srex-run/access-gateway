import http from "k6/http";
import {check} from "k6";

export const options = {
  scenarios: {
    read_path: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.REQUESTS_PER_SECOND || 20),
      timeUnit: "1s",
      duration: __ENV.DURATION || "5m",
      preAllocatedVUs: Number(__ENV.PREALLOCATED_VUS || 20),
      maxVUs: Number(__ENV.MAX_VUS || 100)
    }
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500", "p(99)<1500"]
  }
};

const base = (__ENV.BASE_URL || "").replace(/\/$/, "");
if (!base.startsWith("https://")) throw new Error("BASE_URL must be an HTTPS origin");
if (!__ENV.SESSION_COOKIE) throw new Error("SESSION_COOKIE is required");

export default function () {
  const response = http.get(`${base}/api/v1/regions`, {headers: {Cookie: __ENV.SESSION_COOKIE}, redirects: 0});
  check(response, {"directory returned 200": value => value.status === 200});
}
