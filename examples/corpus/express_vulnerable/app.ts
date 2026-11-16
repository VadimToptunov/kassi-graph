import express from 'express';
import { prisma } from './db';
import { requireAuth, checkOwnership } from './middleware';

const app = express();

// UNGUARDED — fetches any user by id, no check
app.get('/users/:id', getUserDetails);

async function getUserDetails(req: express.Request, res: express.Response) {
  const user = await prisma.user.findUnique({ where: { id: req.params.id } });
  res.json(user);
}

// UNGUARDED — delete any post, only authn check (if even that)
app.delete('/posts/:id', deleteAnyPost);

async function deleteAnyPost(req: express.Request, res: express.Response) {
  await prisma.post.delete({ where: { id: req.params.id } });
  res.json({ ok: true });
}

// GUARDED — explicit ownership check before delete
app.delete('/comments/:id', safeDeleteComment);

async function safeDeleteComment(req: express.Request, res: express.Response) {
  const ok = await checkOwnership(req, req.params.id);
  if (!ok) { res.status(403).json({ error: 'forbidden' }); return; }
  await prisma.comment.delete({ where: { id: req.params.id } });
  res.json({ ok: true });
}

// GUARDED — no caller-controlled param, uses session
app.get('/me', safeMyProfile);

async function safeMyProfile(req: express.Request, res: express.Response) {
  const user = await prisma.user.findUnique({ where: { id: (req as any).session.userId } });
  res.json(user);
}

export { app };
