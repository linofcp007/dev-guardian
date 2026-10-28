/**
 * Background jobs named like payment events — `invoice.generate`,
 * `subscription.renew` — compared on a field that is not an event type
 * (`job.name`, `task.kind`). Not a webhook: nothing fires.
 */

declare function render(x: unknown): Promise<void>;

export async function runJob(job: { name: string; data: unknown }) {
  if (job.name === 'invoice.generate') await render(job.data);
  switch (job.name) {
    case 'subscription.renew':
      await render(job.data);
  }
}
