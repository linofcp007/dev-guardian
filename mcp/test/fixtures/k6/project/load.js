// A smoke load test laid out as grafana/quickpizza's k6/foundations scripts are: the load shapes in a module,
// the requests in another, test data opened from data/. Test data for dev-guardian's k6 tests (not copied).
import http from 'k6/http';
import { SmokeOptions } from './lib/load-options.js';
import { BASE_URL } from './lib/target.js';
import {
  getHome,
  getRecommendation,
} from './lib/frontend/basic.js';
// import { SpikeStages } from './lib/spike-stages.js';

const tokens = JSON.parse(open('./data/tokens.json'));

export const options = SmokeOptions;

export default function () {
  getHome(http, BASE_URL);
  getRecommendation(http, BASE_URL, tokens[0]);
}
