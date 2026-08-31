/** Report generation page. */
import { FileText } from "lucide-react";

type ReportsProps = {
  onGenerate: () => void;
  onBack?: () => void;
};

export function Reports({ onGenerate }: ReportsProps) {
  return (
    <section className="panel">
      <p className="eyebrow">CLIENT DELIVERABLE</p>
      <h2>Assessment reports</h2>
      <p className="muted">
        Generate and download a PDF report containing the current project and
        normalized findings.
      </p>
      <button onClick={onGenerate}>
        <FileText size={15} /> Generate PDF report
      </button>
    </section>
  );
}
