import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { initializeApp, getApps } from 'firebase/app';
import { getFirestore, doc, getDoc, setDoc } from 'firebase/firestore';

export interface StoredUser {
  id: string;
  nome: string;
  username: string;
  email: string;
  passwordHash: string;
  passwordSalt: string;
  role: 'ADMINISTRADOR' | 'OPERADOR';
  ativo: boolean;
  termoAceito?: boolean;
  termoAceitoEm?: string;
  createdAt: string;
  updatedAt: string;
}

export type SafeUser = Omit<StoredUser, 'passwordHash' | 'passwordSalt'>;

export interface SessionData {
  token: string;
  userId: string;
  username: string;
  nome: string;
  role: 'ADMINISTRADOR' | 'OPERADOR';
  createdAt: string;
  expiresAt: number;
}

export interface AuditLog {
  id: string;
  usuario: string;
  userId?: string;
  dataHora: string;
  acao: string;
  recurso: string;
  resultado: 'SUCESSO' | 'FALHA' | 'BLOQUEADO';
  detalhes?: string;
}

interface DataStore {
  users: StoredUser[];
  auditLogs: AuditLog[];
  sessions?: Record<string, SessionData>;
}

const DATA_DIR = path.join(process.cwd(), 'data');
const STORE_FILE = path.join(DATA_DIR, 'redevigia_store.json');

// In-memory active sessions: token -> SessionData
const activeSessions = new Map<string, SessionData>();

export function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

export function generateSalt(): string {
  return crypto.randomBytes(16).toString('hex');
}

export function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

function ensureUniqueUserIds(users: StoredUser[]): boolean {
  let changed = false;
  const seen = new Set<string>();
  for (let i = 0; i < users.length; i++) {
    const u = users[i];
    if (!u.id || seen.has(u.id)) {
      const base = u.id || 'user';
      let suffix = 1;
      let candidate = `${base}_${suffix}`;
      while (seen.has(candidate)) {
        suffix++;
        candidate = `${base}_${suffix}`;
      }
      u.id = candidate;
      changed = true;
    }
    seen.add(u.id);
  }
  return changed;
}

function loadStore(): DataStore {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    if (fs.existsSync(STORE_FILE)) {
      const raw = fs.readFileSync(STORE_FILE, 'utf-8');
      const parsed: DataStore = JSON.parse(raw);

      // Restore active sessions that have not expired
      if (parsed.sessions && typeof parsed.sessions === 'object') {
        const now = Date.now();
        for (const [t, s] of Object.entries(parsed.sessions)) {
          if (s && s.expiresAt > now) {
            activeSessions.set(t, s);
          }
        }
      }

      // ALTERAÇÃO: Sincronização automática para garantir que login (username) seja sempre idêntico ao e-mail
      let hasChanges = false;
      for (const u of parsed.users) {
        if (u.email && u.username !== u.email) {
          u.username = u.email;
          hasChanges = true;
        }
      }

      // ALTERAÇÃO: Garantir credencial padrão para o administrador: teste@redevigia e senha 1353986LEOrv@
      const defaultAdminLogin = 'teste@redevigia';
      const defaultAdminPass = process.env.INITIAL_ADMIN_PASSWORD || '1353986LEOrv@';

      let adminAccount = parsed.users.find(
        u => u.username.toLowerCase() === defaultAdminLogin.toLowerCase() || u.email.toLowerCase() === defaultAdminLogin.toLowerCase()
      );

      if (!adminAccount) {
        const adminSalt = generateSalt();
        const rootIdTaken = parsed.users.some(u => u.id === 'user_admin_root');
        parsed.users.unshift({
          id: rootIdTaken ? 'user_admin_teste' : 'user_admin_root',
          nome: 'Administrador do Sistema (Admin Central)',
          username: defaultAdminLogin,
          email: defaultAdminLogin,
          passwordSalt: adminSalt,
          passwordHash: hashPassword(defaultAdminPass, adminSalt),
          role: 'ADMINISTRADOR',
          ativo: true,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        });
        hasChanges = true;
      } else {
        // Garantir que a senha seja 1353986LEOrv@
        const expectedHash = hashPassword(defaultAdminPass, adminAccount.passwordSalt);
        if (expectedHash !== adminAccount.passwordHash) {
          const newSalt = generateSalt();
          adminAccount.passwordSalt = newSalt;
          adminAccount.passwordHash = hashPassword(defaultAdminPass, newSalt);
          adminAccount.ativo = true;
          hasChanges = true;
        }
      }
      if (ensureUniqueUserIds(parsed.users)) {
        hasChanges = true;
      }
      if (hasChanges) {
        saveStore(parsed);
      }
      return parsed;
    }
  } catch (err) {
    console.error('Erro ao ler store de dados:', err);
  }

  // Initial Seed
  const initialAdminPass = process.env.INITIAL_ADMIN_PASSWORD || '1353986LEOrv@';
  const adminSalt = generateSalt();
  const opSalt1 = generateSalt();
  const opSalt2 = generateSalt();

  const now = new Date().toISOString();

  const initialStore: DataStore = {
    users: [
      {
        id: 'user_admin_root',
        nome: 'Administrador do Sistema (Admin Central)',
        username: 'teste@redevigia',
        email: 'teste@redevigia',
        passwordSalt: adminSalt,
        passwordHash: hashPassword(initialAdminPass, adminSalt),
        role: 'ADMINISTRADOR',
        ativo: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'user_op_marcos',
        nome: 'Marcos Lima (Operador A)',
        username: 'operador',
        email: 'marcos.op@redevigia.gov.br',
        passwordSalt: opSalt1,
        passwordHash: hashPassword('op123', opSalt1),
        role: 'OPERADOR',
        ativo: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'user_op_juliana',
        nome: 'Juliana Souza (Operadora B)',
        username: 'juliana',
        email: 'juliana.op@redevigia.gov.br',
        passwordSalt: opSalt2,
        passwordHash: hashPassword('juliana123', opSalt2),
        role: 'OPERADOR',
        ativo: true,
        createdAt: now,
        updatedAt: now
      }
    ],
    auditLogs: [
      {
        id: 'audit_init',
        usuario: 'SISTEMA',
        dataHora: now,
        acao: 'SISTEMA_INICIALIZADO',
        recurso: 'autenticacao',
        resultado: 'SUCESSO',
        detalhes: 'Base de dados de autenticação da REDE VIGIA inicializada com segurança.'
      }
    ]
  };

  saveStore(initialStore);
  return initialStore;
}

function getFirebaseConfig() {
  const envKey = process.env.VITE_FIREBASE_API_KEY || process.env.FIREBASE_API_KEY;
  if (envKey) {
    return {
      projectId: process.env.VITE_FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT_ID || 'gen-lang-client-0401009492',
      appId: process.env.VITE_FIREBASE_APP_ID || process.env.FIREBASE_APP_ID || '',
      apiKey: envKey,
      authDomain: process.env.VITE_FIREBASE_AUTH_DOMAIN || process.env.FIREBASE_AUTH_DOMAIN || '',
      firestoreDatabaseId: process.env.VITE_FIREBASE_DATABASE_ID || process.env.FIREBASE_DATABASE_ID || 'ai-studio-8be4614b-b0f9-4347-8939-c357b447fcbb',
      storageBucket: process.env.VITE_FIREBASE_STORAGE_BUCKET || process.env.FIREBASE_STORAGE_BUCKET || '',
      messagingSenderId: process.env.VITE_FIREBASE_MESSAGING_SENDER_ID || process.env.FIREBASE_MESSAGING_SENDER_ID || '',
    };
  }
  try {
    const configPath = path.join(process.cwd(), 'firebase-applet-config.json');
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    }
  } catch (e) {}
  return null;
}

let backendDb: any = null;
function getBackendFirestore() {
  if (backendDb) return backendDb;
  try {
    const cfg = getFirebaseConfig();
    if (!cfg || !cfg.apiKey) return null;
    const app = getApps().find(a => a.name === 'redevigia-backend') || initializeApp(cfg, 'redevigia-backend');
    backendDb = getFirestore(app, cfg.firestoreDatabaseId);
    return backendDb;
  } catch (err) {
    console.warn('Aviso: Firestore backend não inicializado:', err);
    return null;
  }
}

export async function syncStoreToFirestore(store: DataStore): Promise<void> {
  try {
    const db = getBackendFirestore();
    if (!db) return;
    const docRef = doc(db, 'system_auth', 'store');
    await Promise.race([
      setDoc(docRef, {
        users: store.users,
        auditLogs: store.auditLogs.slice(0, 300),
        sessions: Object.fromEntries(activeSessions),
        updatedAt: new Date().toISOString()
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Firestore sync timeout')), 4000))
    ]);
  } catch (err) {
    console.warn('Aviso ao sincronizar dados com Firestore:', err);
  }
}

export async function syncStoreFromFirestore(): Promise<void> {
  try {
    const db = getBackendFirestore();
    if (!db) return;
    const docRef = doc(db, 'system_auth', 'store');
    const snap = await Promise.race([
      getDoc(docRef),
      new Promise<any>((_, reject) => setTimeout(() => reject(new Error('Firestore read timeout')), 4000))
    ]);
    if (snap && snap.exists()) {
      const data = snap.data() as Partial<DataStore>;
      if (data.users && Array.isArray(data.users) && data.users.length > 0) {
        memoryStore.users = data.users;
        let needsSave = ensureUniqueUserIds(memoryStore.users);
        // Garante que a credencial padrão do administrador permaneça sincronizada com a senha configurada
        const defaultAdminLogin = 'teste@redevigia';
        const defaultAdminPass = process.env.INITIAL_ADMIN_PASSWORD || '1353986LEOrv@';
        const adminAccount = memoryStore.users.find(
          u => u.username.toLowerCase() === defaultAdminLogin || u.email.toLowerCase() === defaultAdminLogin
        );
        if (adminAccount) {
          const expectedHash = hashPassword(defaultAdminPass, adminAccount.passwordSalt);
          if (expectedHash !== adminAccount.passwordHash) {
            const newSalt = generateSalt();
            adminAccount.passwordSalt = newSalt;
            adminAccount.passwordHash = hashPassword(defaultAdminPass, newSalt);
            adminAccount.ativo = true;
            adminAccount.updatedAt = new Date().toISOString();
            needsSave = true;
          }
        }
        if (needsSave) {
          saveStore(memoryStore);
        }
      }
      if (data.auditLogs && Array.isArray(data.auditLogs)) {
        memoryStore.auditLogs = data.auditLogs;
      }
      if (data.sessions && typeof data.sessions === 'object') {
        const now = Date.now();
        for (const [t, s] of Object.entries(data.sessions)) {
          if (s && s.expiresAt > now) {
            activeSessions.set(t, s);
          }
        }
      }
    }
  } catch (err) {
    // Fallback silencioso para arquivo local ou memória
  }
}

function saveStore(store: DataStore) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const dataToSave = {
      ...store,
      sessions: Object.fromEntries(activeSessions)
    };
    fs.writeFileSync(STORE_FILE, JSON.stringify(dataToSave, null, 2), 'utf-8');
  } catch (err) {
    // Não-fatal em ambientes serverless (read-only filesystem)
  }

  // Sincroniza em background com o Firestore para persistência serverless
  syncStoreToFirestore(store).catch(() => {});
}

let memoryStore: DataStore = loadStore();

export function findAdminByEmail(email: string): SafeUser | null {
  memoryStore = loadStore();
  const clean = (email || '').trim().toLowerCase();
  const user = memoryStore.users.find(
    u => (u.email && u.email.toLowerCase() === clean) || (u.username && u.username.toLowerCase() === clean)
  );
  if (user && user.role === 'ADMINISTRADOR' && user.ativo) {
    return toSafeUser(user);
  }
  return null;
}

export function toSafeUser(user: StoredUser): SafeUser {
  const { passwordHash, passwordSalt, ...safe } = user;
  return safe;
}

export function logAudit(entry: Omit<AuditLog, 'id' | 'dataHora'>) {
  const now = new Date().toISOString();
  const log: AuditLog = {
    id: `audit_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    dataHora: now,
    ...entry
  };
  memoryStore.auditLogs.unshift(log);
  // Cap audit logs to last 500 entries
  if (memoryStore.auditLogs.length > 500) {
    memoryStore.auditLogs = memoryStore.auditLogs.slice(0, 500);
  }
  saveStore(memoryStore);
}

export function authenticate(usernameOrEmail: string, passwordPlain: string): {
  success: boolean;
  error?: string;
  token?: string;
  user?: SafeUser;
} {
  memoryStore = loadStore();
  const cleanInput = (usernameOrEmail || '').trim().toLowerCase();
  const user = memoryStore.users.find(
    u => u.username.toLowerCase() === cleanInput || u.email.toLowerCase() === cleanInput
  );

  if (!user) {
    logAudit({
      usuario: usernameOrEmail || 'DESCONHECIDO',
      acao: 'LOGIN_FALHA',
      recurso: 'autenticacao',
      resultado: 'FALHA',
      detalhes: `Tentativa de login com usuário inexistente: "${usernameOrEmail}"`
    });
    return { success: false, error: 'Usuário ou senha inválidos.' };
  }

  if (!user.ativo) {
    logAudit({
      usuario: user.username,
      userId: user.id,
      acao: 'LOGIN_BLOQUEADO',
      recurso: 'autenticacao',
      resultado: 'BLOQUEADO',
      detalhes: `Acesso negado para usuário desativado (${user.nome})`
    });
    return { success: false, error: 'Acesso bloqueado: Este usuário foi desativado pela administração.' };
  }

  const computedHash = hashPassword(passwordPlain, user.passwordSalt);
  if (computedHash !== user.passwordHash) {
    logAudit({
      usuario: user.username,
      userId: user.id,
      acao: 'LOGIN_FALHA',
      recurso: 'autenticacao',
      resultado: 'FALHA',
      detalhes: 'Senha incorreta fornecida.'
    });
    return { success: false, error: 'Usuário ou senha inválidos.' };
  }

  // Authentication successful - create session token valid for 24h
  const token = generateToken();
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
  const session: SessionData = {
    token,
    userId: user.id,
    username: user.username,
    nome: user.nome,
    role: user.role,
    createdAt: new Date().toISOString(),
    expiresAt
  };

  activeSessions.set(token, session);

  logAudit({
    usuario: user.username,
    userId: user.id,
    acao: 'LOGIN_SUCESSO',
    recurso: 'autenticacao',
    resultado: 'SUCESSO',
    detalhes: `Autenticação bem-sucedida. Perfil: ${user.role}`
  });

  return {
    success: true,
    token,
    user: toSafeUser(user)
  };
}

export function validateSession(token: string): SessionData | null {
  if (!token) return null;
  const session = activeSessions.get(token);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return null;
  }

  // Also check if user is still active in database
  const user = memoryStore.users.find(u => u.id === session.userId);
  if (!user || !user.ativo) {
    activeSessions.delete(token);
    return null;
  }

  // Refresh role if it changed in DB
  session.role = user.role;
  session.nome = user.nome;

  return session;
}

export function invalidateSession(token: string): boolean {
  const session = activeSessions.get(token);
  if (session) {
    logAudit({
      usuario: session.username,
      userId: session.userId,
      acao: 'LOGOUT',
      recurso: 'autenticacao',
      resultado: 'SUCESSO',
      detalhes: 'Sessão encerrada voluntariamente pelo usuário.'
    });
    activeSessions.delete(token);
    return true;
  }
  return false;
}

export function getAllUsers(): SafeUser[] {
  return memoryStore.users.map(toSafeUser);
}

export function getUserById(id: string): SafeUser | null {
  const u = memoryStore.users.find(user => user.id === id);
  return u ? toSafeUser(u) : null;
}

export function createUser(
  adminSession: SessionData,
  userData: {
    nome: string;
    username: string;
    email?: string;
    passwordPlain: string;
    role: 'ADMINISTRADOR' | 'OPERADOR';
    ativo: boolean;
  }
): { success: boolean; user?: SafeUser; error?: string } {
  // ALTERAÇÃO: O login do usuário deve ser sempre rigorosamente o seu endereço de e-mail
  const cleanEmail = (userData.email || userData.username || '').trim().toLowerCase();
  if (!cleanEmail || !cleanEmail.includes('@')) {
    return { success: false, error: 'O endereço de e-mail válido é obrigatório para o login.' };
  }

  const cleanUsername = (userData.username || cleanEmail).trim().toLowerCase();
  if (cleanUsername !== cleanEmail) {
    return { success: false, error: 'O login do usuário deve ser estritamente igual ao endereço de e-mail.' };
  }

  if (!userData.passwordPlain || userData.passwordPlain.length < 4) {
    return { success: false, error: 'A senha deve ter pelo menos 4 caracteres.' };
  }

  const existing = memoryStore.users.find(
    u => u.email.toLowerCase() === cleanEmail || u.username.toLowerCase() === cleanEmail
  );
  if (existing) {
    return { success: false, error: 'Este e-mail/login já está cadastrado no sistema.' };
  }

  const salt = generateSalt();
  const hash = hashPassword(userData.passwordPlain, salt);
  const now = new Date().toISOString();

  const newUser: StoredUser = {
    id: `user_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    nome: userData.nome.trim(),
    username: cleanEmail,
    email: cleanEmail,
    passwordSalt: salt,
    passwordHash: hash,
    role: userData.role,
    ativo: userData.ativo,
    createdAt: now,
    updatedAt: now
  };

  memoryStore.users.push(newUser);
  saveStore(memoryStore);

  logAudit({
    usuario: adminSession.username,
    userId: adminSession.userId,
    acao: 'USUARIO_CRIADO',
    recurso: 'usuarios',
    resultado: 'SUCESSO',
    detalhes: `Novo usuário criado: "${newUser.username}" (${newUser.nome}) com perfil ${newUser.role}.`
  });

  return { success: true, user: toSafeUser(newUser) };
}

export function updateUser(
  adminSession: SessionData,
  userId: string,
  updates: {
    nome?: string;
    username?: string;
    role?: 'ADMINISTRADOR' | 'OPERADOR';
    ativo?: boolean;
  }
): { success: boolean; user?: SafeUser; error?: string } {
  memoryStore = loadStore();
  const cleanId = (userId || '').trim().toLowerCase();
  const userIndex = memoryStore.users.findIndex(
    u => u.id === userId || (u as any).uid === userId || (u.email && u.email.toLowerCase() === cleanId)
  );
  if (userIndex === -1) {
    return { success: false, error: 'Usuário não encontrado.' };
  }

  const user = memoryStore.users[userIndex];

  // ALTERAÇÃO: Impedir qualquer tentativa de alterar o login para valor diferente do e-mail
  if (updates.username && updates.username.trim().toLowerCase() !== user.email.toLowerCase()) {
    return { success: false, error: 'O login do usuário é fixo e deve ser sempre igual ao e-mail.' };
  }

  const oldRole = user.role;
  const oldAtivo = user.ativo;

  if (updates.nome !== undefined) user.nome = updates.nome.trim();
  if (updates.role !== undefined) user.role = updates.role;
  if (updates.ativo !== undefined) user.ativo = updates.ativo;
  user.updatedAt = new Date().toISOString();

  saveStore(memoryStore);

  const changes: string[] = [];
  if (updates.role && updates.role !== oldRole) {
    changes.push(`Perfil alterado de ${oldRole} para ${updates.role}`);
  }
  if (updates.ativo !== undefined && updates.ativo !== oldAtivo) {
    changes.push(updates.ativo ? 'Usuário ativado' : 'Usuário desativado');
  }
  if (updates.nome && updates.nome !== user.nome) {
    changes.push('Nome atualizado');
  }

  logAudit({
    usuario: adminSession.username,
    userId: adminSession.userId,
    acao: updates.role && updates.role !== oldRole ? 'ALTERACAO_NIVEL_ACESSO' : 'USUARIO_ALTERADO',
    recurso: 'usuarios',
    resultado: 'SUCESSO',
    detalhes: `Usuário "${user.username}" modificado: ${changes.join(', ') || 'Dados cadastrais atualizados'}`
  });

  return { success: true, user: toSafeUser(user) };
}

export function resetUserPassword(
  adminSession: SessionData,
  userId: string,
  newPasswordPlain: string
): { success: boolean; error?: string } {
  memoryStore = loadStore();
  const cleanId = (userId || '').trim().toLowerCase();
  const user = memoryStore.users.find(
    u => u.id === userId || (u as any).uid === userId || (u.email && u.email.toLowerCase() === cleanId)
  );
  if (!user) {
    return { success: false, error: 'Usuário não encontrado.' };
  }
  if (!newPasswordPlain || newPasswordPlain.length < 4) {
    return { success: false, error: 'A nova senha deve possuir pelo menos 4 caracteres.' };
  }

  const newSalt = generateSalt();
  user.passwordSalt = newSalt;
  user.passwordHash = hashPassword(newPasswordPlain, newSalt);
  user.updatedAt = new Date().toISOString();

  saveStore(memoryStore);

  logAudit({
    usuario: adminSession.username,
    userId: adminSession.userId,
    acao: 'SENHA_REDEFINIDA',
    recurso: 'usuarios',
    resultado: 'SUCESSO',
    detalhes: `Senha redefinida para o usuário "${user.username}".`
  });

  return { success: true };
}

export function changeUserPassword(
  session: SessionData,
  currentPasswordPlain: string,
  newPasswordPlain: string
): { success: boolean; error?: string } {
  if (!currentPasswordPlain) {
    return { success: false, error: 'A senha atual é obrigatória.' };
  }
  if (!newPasswordPlain) {
    return { success: false, error: 'A nova senha é obrigatória.' };
  }
  if (newPasswordPlain.length < 4) {
    return { success: false, error: 'A nova senha deve possuir pelo menos 4 caracteres.' };
  }

  // Ensure store is up to date
  memoryStore = loadStore();

  const user = memoryStore.users.find(u => u.id === session.userId);
  if (!user) {
    return { success: false, error: 'Usuário não encontrado na base de dados.' };
  }

  if (!user.ativo) {
    return { success: false, error: 'Este usuário está desativado no sistema.' };
  }

  const currentHash = hashPassword(currentPasswordPlain, user.passwordSalt);
  if (currentHash !== user.passwordHash) {
    logAudit({
      usuario: user.username,
      userId: user.id,
      acao: 'ALTERACAO_SENHA_FALHA',
      recurso: 'autenticacao',
      resultado: 'FALHA',
      detalhes: 'Tentativa de alteração de senha: senha atual informada está incorreta.'
    });
    return { success: false, error: 'A senha atual informada está incorreta.' };
  }

  const newSalt = generateSalt();
  user.passwordSalt = newSalt;
  user.passwordHash = hashPassword(newPasswordPlain, newSalt);
  user.updatedAt = new Date().toISOString();

  saveStore(memoryStore);

  logAudit({
    usuario: user.username,
    userId: user.id,
    acao: 'SENHA_ALTERADA',
    recurso: 'autenticacao',
    resultado: 'SUCESSO',
    detalhes: 'O operador alterou a sua própria senha com sucesso.'
  });

  return { success: true };
}

export function deleteUser(
  adminSession: SessionData,
  userId: string
): { success: boolean; error?: string } {
  // ALTERAÇÃO: Apenas ao administrador deve ser possível excluir outros usuários
  if (adminSession.role !== 'ADMINISTRADOR') {
    return { success: false, error: 'Apenas o administrador possui permissão para excluir outros usuários.' };
  }

  // Prevent deleting oneself
  if (adminSession.userId === userId) {
    return { success: false, error: 'Você não pode excluir o seu próprio usuário logado.' };
  }

  // Ensure store is up to date
  memoryStore = loadStore();

  const user = memoryStore.users.find(
    u => u.id === userId || (u as any).uid === userId || (u.email && u.email.toLowerCase() === userId.toLowerCase())
  );
  if (!user) {
    return { success: false, error: 'Usuário não encontrado.' };
  }

  // Check self-deletion safety by matched user
  if (user.id === adminSession.userId || (user.email && adminSession.username && user.email.toLowerCase() === adminSession.username.toLowerCase())) {
    return { success: false, error: 'Você não pode excluir o seu próprio usuário logado.' };
  }

  memoryStore.users = memoryStore.users.filter(u => u.id !== user.id);
  saveStore(memoryStore);

  logAudit({
    usuario: adminSession.username,
    userId: adminSession.userId,
    acao: 'USUARIO_EXCLUIDO',
    recurso: 'usuarios',
    resultado: 'SUCESSO',
    detalhes: `Usuário excluído: "${user.username}" (${user.nome}).`
  });

  return { success: true };
}

export function getAuditLogs(): AuditLog[] {
  return memoryStore.auditLogs;
}

export function recoverAdminPassword(
  identifier: string,
  newPasswordPlain?: string
): { success: boolean; error?: string; username?: string; message?: string } {
  // Ensure store is up-to-date with disk
  memoryStore = loadStore();
  const cleanId = (identifier || '').trim().toLowerCase();

  // Locate the administrator account
  let admin = memoryStore.users.find(
    u => u.role === 'ADMINISTRADOR' && (
      !cleanId ||
      u.username.toLowerCase() === cleanId ||
      u.email.toLowerCase() === cleanId ||
      cleanId.includes('admin') ||
      cleanId.includes('leonardhussen')
    )
  );

  if (!admin) {
    admin = memoryStore.users.find(u => u.role === 'ADMINISTRADOR');
  }

  if (!admin) {
    return { success: false, error: 'Nenhum administrador encontrado no sistema.' };
  }

  const newPass = (newPasswordPlain && newPasswordPlain.trim().length >= 4)
    ? newPasswordPlain.trim()
    : 'admin123';

  const newSalt = generateSalt();
  admin.passwordSalt = newSalt;
  admin.passwordHash = hashPassword(newPass, newSalt);
  admin.ativo = true;
  admin.updatedAt = new Date().toISOString();

  // If user passed an email, associate it
  if (cleanId && cleanId.includes('@')) {
    admin.email = cleanId;
  }

  saveStore(memoryStore);

  logAudit({
    usuario: admin.username,
    userId: admin.id,
    acao: 'RECUPERACAO_SENHA_ADMIN',
    recurso: 'autenticacao',
    resultado: 'SUCESSO',
    detalhes: `Senha do administrador redefinida para nova chave com sucesso.`
  });

  return {
    success: true,
    username: admin.username,
    message: `A senha do administrador (${admin.username}) foi recuperada com sucesso.`
  };
}

export function recordOperatorAgreement(userId: string): { success: boolean; error?: string } {
  const user = memoryStore.users.find(u => u.id === userId);
  if (!user) {
    return { success: false, error: 'Usuário não encontrado.' };
  }
  const now = new Date().toISOString();
  user.termoAceito = true;
  user.termoAceitoEm = now;
  user.updatedAt = now;
  saveStore(memoryStore);

  logAudit({
    usuario: user.username,
    userId: user.id,
    acao: 'TERMO_CONCORDANCIA_ACEITO',
    recurso: 'operador_termo',
    resultado: 'SUCESSO',
    detalhes: 'Operador concordou com o termo obrigatório de comunicação de ocorrências e canais oficiais.'
  });

  return { success: true };
}

