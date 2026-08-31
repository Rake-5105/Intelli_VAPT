/** Sidebar navigation button component. */
import type { ReactNode } from "react";

type NavProps = {
  icon: ReactNode;
  label: string;
  active: boolean;
  onClick: () => void;
};

export function Nav({ icon, label, active, onClick }: NavProps) {
  return (
    <button className={active ? "nav active" : "nav"} onClick={onClick}>
      {icon}
      {label}
    </button>
  );
}
