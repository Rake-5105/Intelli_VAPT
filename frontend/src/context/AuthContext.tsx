/**
 * Authentication context — manages token, user state, login, register, and logout.
 * On mount, validates any stored token via /api/auth/me. If invalid, clears it.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { loginRequest, registerRequest, request } from "../api";
import type { User } from "../types";

type AuthContextValue = {
  token: string;
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState(localStorage.getItem("iv_token") || "");
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(!!localStorage.getItem("iv_token"));

  // On mount, if we have a stored token, verify it's still valid
  useEffect(() => {
    const stored = localStorage.getItem("iv_token");
    if (!stored) {
      setLoading(false);
      return;
    }

    request("/api/auth/me", stored)
      .then((userData) => {
        setUser(userData);
        setToken(stored);
      })
      .catch(() => {
        // Token is invalid/expired — clear it so login page shows
        localStorage.removeItem("iv_token");
        setToken("");
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string) {
    const data = await loginRequest(email, password);
    localStorage.setItem("iv_token", data.access_token);
    setUser(data.user);
    setToken(data.access_token);
  }

  async function register(name: string, email: string, password: string) {
    const data = await registerRequest(name, email, password);
    localStorage.setItem("iv_token", data.access_token);
    setUser(data.user);
    setToken(data.access_token);
  }

  function logout() {
    localStorage.removeItem("iv_token");
    setToken("");
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ token, user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
