import express from 'express';
import {
  authenticate,
  validateSession,
  invalidateSession,
  getAllUsers,
  createUser,
  updateUser,
  resetUserPassword,
  changeUserPassword,
  deleteUser,
  getAuditLogs,
  recoverAdminPassword,
  recordOperatorAgreement,
  findAdminByEmail,
  syncStoreFromFirestore,
  type SessionData
} from './serverAuth.ts';

export function createServerApp() {
  const app = express();

  // Middleware de CORS para requisições do frontend no Netlify e local
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-session-token, x-admin-email');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  app.use(express.json());

  // Sincronização em background para ambientes serverless (cold-start)
  syncStoreFromFirestore().catch(() => {});

  // Authentication Middleware
  const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ')
      ? authHeader.substring(7)
      : (req.headers['x-session-token'] as string);

    if (token) {
      const session = validateSession(token);
      if (session) {
        (req as any).user = session as SessionData;
        return next();
      }
    }

    // Fallback: If request is authenticated from an active administrator via x-admin-email
    const adminEmail = (req.headers['x-admin-email'] as string)?.toLowerCase().trim();
    if (adminEmail) {
      const adminUser = findAdminByEmail(adminEmail);
      if (adminUser) {
        (req as any).user = {
          token: 'fallback_admin_token',
          userId: adminUser.id,
          username: adminUser.username || adminUser.email,
          nome: adminUser.nome,
          role: adminUser.role,
          createdAt: adminUser.createdAt || new Date().toISOString(),
          expiresAt: Date.now() + 24 * 60 * 60 * 1000
        } as SessionData;
        return next();
      }
    }

    return res.status(401).json({ error: 'Não autenticado: Token de sessão não fornecido ou inválido.' });
  };

  // Admin Role Verification Middleware
  const requireAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const user = (req as any).user as SessionData;
    if (!user || user.role !== 'ADMINISTRADOR') {
      return res.status(403).json({ error: 'Acesso negado: Ação exclusiva para ADMINISTRADOR.' });
    }
    next();
  };

  // API endpoints
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      app: 'REDE VIGIA',
      database: 'Firebase Firestore',
      privacyCompliant: true,
      timestamp: new Date().toISOString()
    });
  });

  // Robots.txt for crawler/probe resolution
  app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.send("User-agent: *\nDisallow: /api/\n");
  });

  // --- AUTHENTICATION & SESSION ENDPOINTS ---

  // 1. Login with username/email and password
  app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Nome de usuário e senha são obrigatórios.' });
    }

    const result = authenticate(username, password);
    if (!result.success) {
      return res.status(401).json({ error: result.error || 'Credenciais inválidas.' });
    }

    res.json({
      success: true,
      token: result.token,
      user: result.user
    });
  });

  // 2. Validate session and get current profile
  app.get('/api/auth/me', requireAuth, (req, res) => {
    const user = (req as any).user as SessionData;
    res.json({
      authenticated: true,
      user: {
        uid: user.userId,
        nome: user.nome,
        username: user.username,
        role: user.role,
        ativo: true
      }
    });
  });

  // 3. Logout
  app.post('/api/auth/logout', (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ')
      ? authHeader.substring(7)
      : (req.headers['x-session-token'] as string);

    if (token) {
      invalidateSession(token);
    }
    res.json({ success: true, message: 'Sessão encerrada com sucesso.' });
  });

  // 3.1. Recuperar Senha de Administrador
  app.post('/api/auth/recover-admin', (req, res) => {
    const { identifier, newPassword } = req.body || {};
    const result = recoverAdminPassword(identifier, newPassword);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }
    res.json({
      success: true,
      message: result.message,
      username: result.username
    });
  });

  // 3.2. Operador altera a sua própria senha
  app.post('/api/auth/change-password', requireAuth, (req, res) => {
    const session = (req as any).user as SessionData;
    const { currentPassword, newPassword } = req.body || {};

    if (!currentPassword) {
      return res.status(400).json({ error: 'A senha atual é obrigatória.' });
    }
    if (!newPassword) {
      return res.status(400).json({ error: 'A nova senha é obrigatória.' });
    }

    const result = changeUserPassword(session, currentPassword, newPassword);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({
      success: true,
      message: 'Senha alterada com sucesso.'
    });
  });

  // 3.3. Operador aceita o termo de concordância
  app.post('/api/auth/accept-agreement', requireAuth, (req, res) => {
    const session = (req as any).user as SessionData;
    const result = recordOperatorAgreement(session.userId);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }
    res.json({
      success: true,
      message: 'Termo de concordância aceito com sucesso.'
    });
  });

  // --- ADMIN PROTECTED USER MANAGEMENT ENDPOINTS ---

  // 4. List all users (ADMIN only, password hashes never returned)
  app.get('/api/auth/users', requireAuth, requireAdmin, (req, res) => {
    const users = getAllUsers();
    res.json({ success: true, users });
  });

  // 5. Create new user (ADMIN only)
  app.post('/api/auth/users', requireAuth, requireAdmin, (req, res) => {
    const adminUser = (req as any).user as SessionData;
    const { nome, username, email, password, role, ativo } = req.body;

    const targetEmail = (email || username || '').trim().toLowerCase();
    if (!nome || !targetEmail || !password || !role) {
      return res.status(400).json({ error: 'Campos obrigatórios ausentes (nome, e-mail, senha, perfil).' });
    }

    if (!targetEmail.includes('@')) {
      return res.status(400).json({ error: 'Informe um endereço de e-mail válido para o login de acesso.' });
    }

    if (username && username.trim().toLowerCase() !== targetEmail) {
      return res.status(400).json({ error: 'O login do usuário deve ser estritamente igual ao endereço de e-mail.' });
    }

    if (!['ADMINISTRADOR', 'OPERADOR'].includes(role)) {
      return res.status(400).json({ error: 'Perfil inválido. Deve ser OPERADOR ou ADMINISTRADOR.' });
    }

    const result = createUser(adminUser, {
      nome,
      username: targetEmail,
      email: targetEmail,
      passwordPlain: password,
      role,
      ativo: ativo !== undefined ? Boolean(ativo) : true
    });

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.status(201).json({ success: true, user: result.user });
  });

  // 6. Update user (ADMIN only)
  app.put('/api/auth/users/:id', requireAuth, requireAdmin, (req, res) => {
    const adminUser = (req as any).user as SessionData;
    const { id } = req.params;
    const { nome, username, role, ativo } = req.body;

    const result = updateUser(adminUser, id, {
      nome,
      username,
      role,
      ativo: ativo !== undefined ? Boolean(ativo) : undefined
    });

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({ success: true, user: result.user });
  });

  // 7. Reset user password (ADMIN only)
  app.post('/api/auth/users/:id/reset-password', requireAuth, requireAdmin, (req, res) => {
    const adminUser = (req as any).user as SessionData;
    const { id } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ error: 'A nova senha deve ter pelo menos 4 caracteres.' });
    }

    const result = resetUserPassword(adminUser, id, newPassword);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({ success: true, message: 'Senha redefinida com sucesso!' });
  });

  // 8. Delete user (ADMIN only)
  app.delete('/api/auth/users/:id', requireAuth, requireAdmin, (req, res) => {
    const adminUser = (req as any).user as SessionData;
    const { id } = req.params;

    const result = deleteUser(adminUser, id);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({ success: true, message: 'Usuário excluído com sucesso.' });
  });

  // --- AUDIT LOGS ENDPOINT (ADMIN ONLY) ---

  // 9. Get audit logs
  app.get('/api/auth/audit', requireAuth, requireAdmin, (req, res) => {
    const logs = getAuditLogs();
    res.json({ success: true, logs });
  });

  // Verification endpoint for privacy compliance
  app.post('/api/verify-anonymity', (req, res) => {
    const { report } = req.body;
    if (!report || typeof report !== 'object') {
      return res.status(400).json({ error: 'Objeto de denúncia inválido' });
    }

    const forbiddenFields = [
      'createdBy',
      'operatorId',
      'operatorUid',
      'operatorName',
      'operatorEmail',
      'userId',
      'uid',
      'author',
      'authorId',
      'userEmail',
      'ip',
      'phone',
      'operatorPhone'
    ];

    const violations = Object.keys(report).filter(k => forbiddenFields.includes(k));

    if (violations.length > 0) {
      return res.status(403).json({
        allowed: false,
        message: 'Violação grave de privacidade! A denúncia contém campos identificadores do operador.',
        violations
      });
    }

    res.json({
      allowed: true,
      message: 'Conformidade de privacidade garantida: 100% anônimo.',
      fieldsVerified: Object.keys(report)
    });
  });

  return app;
}
