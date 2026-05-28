import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, isApiError, type User } from './api';

interface AuthState {
  user: User | null;
  loading: boolean;
  needsBootstrap: boolean;
  /**
   * When set after login, the user has a pre-auth session and must call
   * verify2fa(code) before any other API call will succeed. Cleared when
   * verify2fa() succeeds OR the user logs out.
   */
  awaiting2fa: boolean;
  refresh: () => Promise<void>;
  login: (email: string, password: string) => Promise<{ requires_2fa: boolean }>;
  signup: (email: string, name: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  verify2fa: (code: string) => Promise<void>;
}

const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsBootstrap, setNeedsBootstrap] = useState(false);
  const [awaiting2fa, setAwaiting2fa] = useState(false);

  const refresh = async () => {
    setLoading(true);
    try {
      const { needsBootstrap } = await api.bootstrap();
      setNeedsBootstrap(needsBootstrap);
      if (needsBootstrap) {
        setUser(null);
      } else {
        try {
          const { user } = await api.me();
          setUser(user);
        } catch (e) {
          // 401 is normal (no session); other errors deserve user visibility.
          if (isApiError(e) && e.status !== 401 && e.status !== 0) {
            console.error(`[auth] /api/auth/me failed: ${e.message}`);
          }
          setUser(null);
        }
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);

  const login = async (email: string, password: string): Promise<{ requires_2fa: boolean }> => {
    const r = await api.login(email, password);
    setUser(r.user);
    setNeedsBootstrap(false);
    setAwaiting2fa(r.requires_2fa === true);
    return { requires_2fa: r.requires_2fa === true };
  };
  const signup = async (email: string, name: string, password: string) => {
    const { user } = await api.signup(email, name, password);
    setUser(user);
    setNeedsBootstrap(false);
    setAwaiting2fa(false);
  };
  const logout = async () => {
    await api.logout();
    setUser(null);
    setAwaiting2fa(false);
  };
  const verify2fa = async (code: string) => {
    await api.twoFaVerify(code);
    setAwaiting2fa(false);
  };

  return (
    <AuthCtx.Provider value={{ user, loading, needsBootstrap, awaiting2fa, refresh, login, signup, logout, verify2fa }}>
      {children}
    </AuthCtx.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error('useAuth must be inside AuthProvider');
  return ctx;
}
