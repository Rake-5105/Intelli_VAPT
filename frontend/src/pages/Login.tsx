/**
 * Login / Register page — adapted from Template 2 with IntelliVAPT branding.
 * Connects to /api/auth/login and /api/auth/register via AuthContext.
 */
import { useState, type FormEvent } from "react";
import { Sun, Moon, ShieldCheck, Check } from "lucide-react";

type AuthPageProps = {
  onLogin: (e: FormEvent<HTMLFormElement>) => void;
  onRegister: (e: FormEvent<HTMLFormElement>) => void;
  error: string;
  theme?: "dark" | "light";
  onToggleTheme?: () => void;
};

export function Login({ onLogin, onRegister, error, theme = "dark", onToggleTheme }: AuthPageProps) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [emailErr, setEmailErr] = useState("");
  const [passErr, setPassErr] = useState("");
  const [nameErr, setNameErr] = useState("");
  const [confirmErr, setConfirmErr] = useState("");
  const [submitting, setSubmitting] = useState(false);

  function clearErrors() {
    setEmailErr("");
    setPassErr("");
    setNameErr("");
    setConfirmErr("");
  }

  function validateEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function validatePassword(password: string): boolean {
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/.test(password);
  }

  async function handleLogin(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    clearErrors();
    const fd = new FormData(e.currentTarget);
    const email = (fd.get("email") as string).trim();
    const password = (fd.get("password") as string).trim();

    if (!email) { setEmailErr("Email cannot be empty"); return; }
    if (!validateEmail(email)) { setEmailErr("Please enter a valid email address"); return; }
    if (!password) { setPassErr("Password cannot be empty"); return; }

    setSubmitting(true);
    try {
      await onLogin(e);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRegister(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    clearErrors();
    const fd = new FormData(e.currentTarget);
    const name = (fd.get("name") as string).trim();
    const email = (fd.get("email") as string).trim();
    const password = (fd.get("password") as string).trim();
    const confirm = (fd.get("confirm_password") as string).trim();

    if (!name || name.length < 3) { setNameErr("Full name must be at least 3 characters"); return; }
    if (!validateEmail(email)) { setEmailErr("Please enter a valid email address"); return; }
    if (!password) { setPassErr("Password cannot be empty"); return; }
    if (password.length < 12) { setPassErr("Password must be at least 12 characters"); return; }
    if (!validatePassword(password)) {
      setPassErr("Must include uppercase, lowercase, a number, and a special character");
      return;
    }
    if (password !== confirm) { setConfirmErr("Passwords do not match"); return; }

    setSubmitting(true);
    try {
      await onRegister(e);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="auth-page">
      {onToggleTheme && (
        <button
          type="button"
          className="auth-theme-toggle"
          onClick={onToggleTheme}
          aria-label={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
          title={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
        >
          {theme === "dark" ? (
            <>
              <Sun size={15} className="theme-toggle-icon sun" />
              <span>Light Mode</span>
            </>
          ) : (
            <>
              <Moon size={15} className="theme-toggle-icon moon" />
              <span>Dark Mode</span>
            </>
          )}
        </button>
      )}

      <div className={`auth-container ${mode === "register" ? "auth-register-mode" : ""}`}>
        {/* ── Form Side ── */}
        <div className="auth-form-side">
          <header className="auth-header">
            <div className="auth-brand">
              <ShieldCheck size={18} className="auth-brand-icon" />
              <span>INTELLIVAPT SUITE</span>
            </div>
            <h1>{mode === "login" ? "Welcome Back" : "Create Account"}</h1>
            <p>
              {mode === "login"
                ? "Sign in to access your security assessments"
                : "Get started with automated VAPT workflows"}
            </p>
          </header>

          {/* ── Login Form ── */}
          {mode === "login" && (
            <form id="loginForm" onSubmit={handleLogin} noValidate>
              <div className="auth-field">
                <label htmlFor="auth-email">Email</label>
                <input
                  type="email"
                  id="auth-email"
                  name="email"
                  placeholder="admin@intellivapt.local"
                  autoComplete="email"
                  required
                />
                {emailErr && <div className="auth-error" aria-live="polite">{emailErr}</div>}
              </div>

              <div className="auth-field">
                <label htmlFor="auth-password">Password</label>
                <input
                  type="password"
                  id="auth-password"
                  name="password"
                  placeholder="••••••••••••"
                  autoComplete="current-password"
                  required
                />
                {passErr && <div className="auth-error" aria-live="polite">{passErr}</div>}
              </div>

              {error && <div className="auth-error auth-error-global">{error}</div>}

              <button
                type="submit"
                className="auth-submit-btn"
                id="auth-login-btn"
                disabled={submitting}
              >
                {submitting ? "Signing in…" : "Sign In"}
              </button>

              <div className="auth-switch">
                <p>Don't have an account?</p>
                <button type="button" onClick={() => { setMode("register"); clearErrors(); }}>
                  Register
                </button>
              </div>

              <div className="auth-divider">Or Continue With</div>
              <div className="auth-socials">
                <a className="auth-social-icon" href="#" title="Google">
                  <img src="/auth-assets/Google.png" alt="Google" />
                </a>
                <a className="auth-social-icon" href="#" title="GitHub">
                  <img src="/auth-assets/Github.png" alt="GitHub" />
                </a>
                <a className="auth-social-icon" href="#" title="Facebook">
                  <img src="/auth-assets/Facebook.png" alt="Facebook" />
                </a>
              </div>
            </form>
          )}

          {/* ── Register Form ── */}
          {mode === "register" && (
            <form id="registerForm" onSubmit={handleRegister} noValidate>
              <div className="auth-field">
                <label htmlFor="auth-name">Full Name</label>
                <input
                  type="text"
                  id="auth-name"
                  name="name"
                  placeholder="John Doe"
                  autoComplete="name"
                  required
                />
                {nameErr && <div className="auth-error" aria-live="polite">{nameErr}</div>}
              </div>

              <div className="auth-field">
                <label htmlFor="auth-reg-email">Email</label>
                <input
                  type="email"
                  id="auth-reg-email"
                  name="email"
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                />
                {emailErr && <div className="auth-error" aria-live="polite">{emailErr}</div>}
              </div>

              <div className="auth-field">
                <label htmlFor="auth-reg-password">Password</label>
                <input
                  type="password"
                  id="auth-reg-password"
                  name="password"
                  placeholder="••••••••••••"
                  autoComplete="new-password"
                  required
                />
                {passErr && <div className="auth-error" aria-live="polite">{passErr}</div>}
              </div>

              <div className="auth-field">
                <label htmlFor="auth-reg-confirm">Confirm Password</label>
                <input
                  type="password"
                  id="auth-reg-confirm"
                  name="confirm_password"
                  placeholder="••••••••••••"
                  autoComplete="new-password"
                  required
                />
                {confirmErr && <div className="auth-error" aria-live="polite">{confirmErr}</div>}
              </div>

              <div className="auth-terms">
                <input type="checkbox" id="auth-agree" name="agree" required />
                <label htmlFor="auth-agree">
                  I agree to the <a href="#">Terms</a> and <a href="#">Privacy Policy</a>
                </label>
              </div>

              {error && <div className="auth-error auth-error-global">{error}</div>}

              <button
                type="submit"
                className="auth-submit-btn"
                id="auth-register-btn"
                disabled={submitting}
              >
                {submitting ? "Creating account…" : "Create Account"}
              </button>

              <div className="auth-switch">
                <p>Already have an account?</p>
                <button type="button" onClick={() => { setMode("login"); clearErrors(); }}>
                  Sign In
                </button>
              </div>

              <div className="auth-divider">Or Continue With</div>
              <div className="auth-socials">
                <a className="auth-social-icon" href="#" title="Google">
                  <img src="/auth-assets/Google.png" alt="Google" />
                </a>
                <a className="auth-social-icon" href="#" title="GitHub">
                  <img src="/auth-assets/Github.png" alt="GitHub" />
                </a>
                <a className="auth-social-icon" href="#" title="Facebook">
                  <img src="/auth-assets/Facebook.png" alt="Facebook" />
                </a>
              </div>
            </form>
          )}
        </div>

        {/* ── Visual Side ── */}
        <div className="auth-visual-side">
          <div className="auth-visual-content">
            <div className="auth-visual-icon">
              <ShieldCheck size={36} />
            </div>
            <h2>IntelliVAPT Suite</h2>
            <p>
              Attack surface intelligence, vulnerability assessment,
              evidence correlation, and remediation workflows —
              all in one platform.
            </p>
            <ul className="auth-features">
              <li>
                <span className="auth-feature-dot">
                  <Check size={10} strokeWidth={3} />
                </span>
                <span>Automated Security Scanning</span>
              </li>
              <li>
                <span className="auth-feature-dot">
                  <Check size={10} strokeWidth={3} />
                </span>
                <span>Real-time Vulnerability Detection</span>
              </li>
              <li>
                <span className="auth-feature-dot">
                  <Check size={10} strokeWidth={3} />
                </span>
                <span>Comprehensive PDF Reports</span>
              </li>
              <li>
                <span className="auth-feature-dot">
                  <Check size={10} strokeWidth={3} />
                </span>
                <span>Remediation Tracking</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </main>
  );
}
