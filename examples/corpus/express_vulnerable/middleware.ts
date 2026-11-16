// Stub middleware.
export function requireAuth(req: any, res: any, next: any) {
  next();
}

export async function checkOwnership(req: any, id: string): Promise<boolean> {
  return (req as any).session?.userId === id;
}
