/**
 * client-identity-from-request, safe: names a request has, on objects that
 * are not a request parameter of any enclosing function. A local options
 * object, a cache's `get('userId')`, a Vue route's params, a `fetch`
 * response's `json()`, and search parameters of a URL the code built itself.
 */

import { useRoute } from 'vue-router';

export async function exportFor(job: { id: string }) {
  const opts = { query: { userId: job.id } };
  return prisma.export.create({ data: { userId: opts.query.userId } });
}

export async function warm() {
  const userId = cache.get('userId');
  return prisma.session.findMany({ where: { userId } });
}

export function useOrders() {
  const route = useRoute();
  return db.orders.find({ userId: route.params.userId });
}

export async function sync(url: string) {
  const response = await fetch(url);
  const remote = await response.json();
  await prisma.mirror.create({ data: { ownerId: remote.ownerId } });
}

export async function syncOwner(url: string) {
  const response = await fetch(url);
  const { ownerId } = await response.json();
  await prisma.mirror.upsert({ where: { ownerId }, create: { ownerId }, update: {} });
}

export async function fromLink(link: string) {
  const { searchParams } = new URL(link);
  await prisma.invite.findMany({ where: { tenantId: searchParams.get('tenantId') } });
}

export async function fromLinkVariable(link: string) {
  const { searchParams } = new URL(link);
  const tenantId = searchParams.get('tenantId');
  await prisma.invite.findMany({ where: { tenantId } });
}
