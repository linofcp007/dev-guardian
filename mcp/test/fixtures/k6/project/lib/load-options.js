// The load shapes, kept in one module as quickpizza's lib/load-options.js keeps them.
export const SmokeOptions = {
  vus: 1,
  iterations: 2,
  thresholds: {
    http_req_duration: ['p(95)<5000'],
  },
};

export const AverageStages = [
  { duration: '30s', target: 20 },
  { duration: '1m', target: 20 },
  { duration: '10s', target: 0 },
];
