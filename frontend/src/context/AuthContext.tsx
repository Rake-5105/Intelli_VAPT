/**
 * Authentication context — manages token, user state, login, and logout.
 */
import { createContext, useContext, useState, type ReactNode } from "react";
import { loginRequest } from "../api";
import type { User } from "../types";

type AuthContextValue = {
  token: string;
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState(localStorage.getItem("iv_token") || "");
  const [user, setUser] = useState<User | null>(null);

  async function login(email: string, password: string) {
    const data = await loginRequest(email, password);
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
    <AuthContext.Provider value={{ token, user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
