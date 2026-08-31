/** Login page component. */
import type { FormEvent } from "react";

type LoginProps = {
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
  error: string;
};

export function Login({ onSubmit, error }: LoginProps) {
  return (
    <main className="login">
      <section>
        <p className="eyebrow">AUTHORIZED ASSESSMENTS ONLY</p>
        <h1>
          Intelli<span>VAPT</span>
        </h1>
        <p>
          Attack surface intelligence, evidence correlation, and remediation
          workflows.
        </p>
        <form onSubmit={onSubmit}>
          <label>
            Email
            <input
              name="email"
              type="email"
              defaultValue="demo@intellivapt.example.com"
              required
            />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              defaultValue="DemoPassword!2026"
              required
            />
          </label>
          {error && <small>{error}</small>}
          <button>Sign in</button>
        </form>
      </section>
    </main>
  );
}
