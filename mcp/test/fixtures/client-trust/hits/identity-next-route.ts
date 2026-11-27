/**
 * client-identity-from-request in Next.js route handlers: the owner read from
 * the parsed body (`await req.json()`) or from the URL's search parameters
 * (`new URL(req.url)`, `req.nextUrl.searchParams`), next to a session the
 * handler checked and then did not use.
 */

import { NextRequest } from 'next/server';
import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/db';

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response(null, { status: 401 });
  const body = await req.json();
  const post = await prisma.post.create({ data: { title: body.title, authorId: body.authorId } }); // BUG: client-identity-from-request -- the parsed body
  return Response.json(post);
}

export async function PUT(req: Request) {
  const { tenantId, plan } = await req.json();
  await prisma.subscription.update({ where: { tenantId }, data: { plan } }); // BUG: client-identity-from-request -- destructured from the parsed body
  return Response.json({ ok: true });
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const tenantId = searchParams.get('tenantId');
  const rows = await prisma.invoice.findMany({ where: { tenantId } }); // BUG: client-identity-from-request -- a search parameter
  return Response.json(rows);
}

export async function PATCH(req: Request) {
  const { searchParams } = new URL(req.url);
  await prisma.invoice.updateMany({ where: { tenantId: searchParams.get('tenantId') }, data: { paid: true } }); // BUG: client-identity-from-request -- a search parameter, direct
  return new Response(null, { status: 204 });
}

export async function DELETE(request: NextRequest) {
  await prisma.upload.deleteMany({ where: { ownerId: request.nextUrl.searchParams.get('ownerId') } }); // BUG: client-identity-from-request -- nextUrl
  return new Response(null, { status: 204 });
}
