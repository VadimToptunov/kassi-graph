// Stub prisma client
export const prisma = {
  user: {
    findUnique: async (_opts: any) => ({ id: 1, email: 'x' }),
    delete: async (_opts: any) => ({}),
  },
  post: {
    findUnique: async (_opts: any) => ({ id: 1 }),
    delete: async (_opts: any) => ({}),
  },
  comment: {
    delete: async (_opts: any) => ({}),
  },
};
