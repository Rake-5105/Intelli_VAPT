/** Metric card component for the overview dashboard. */

type MetricProps = {
  label: string;
  value: number;
  alert?: boolean;
};

export function Metric({ label, value, alert = false }: MetricProps) {
  return (
    <article className={alert ? "metric alert" : "metric"}>
      <p>{label}</p>
      <strong>{value}</strong>
    </article>
  );
}
