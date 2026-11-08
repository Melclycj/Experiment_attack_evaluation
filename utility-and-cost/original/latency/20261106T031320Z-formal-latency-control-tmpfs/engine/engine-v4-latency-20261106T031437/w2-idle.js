// k6 idle load: one VU that only sleeps. No requests are made.
import { sleep } from 'k6';
export const options = {
  scenarios: { idle: { executor: 'constant-vus', vus: 1, duration: '24h', gracefulStop: '0s' } },
};
export default function () { sleep(3600); }
