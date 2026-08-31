/** Remediation tracking page. */
import { Table } from "../components/Table";
import type { Finding } from "../types";

type RemediationProps = {
  findings: Finding[];
};

export function Remediation({ findings }: RemediationProps) {
  return (
    <Table
      headers={["Finding", "Severity", "Status", "Remediation"]}
      rows={findings.map((f) => [f.title, f.severity, f.status, f.remediation])}
      empty="No remediation tasks yet."
    />
  );
}
