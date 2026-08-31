/** Reusable table component with header row and empty state. */

type TableProps = {
  headers: string[];
  rows: string[][];
  empty: string;
};

export function Table({ headers, rows, empty }: TableProps) {
  return (
    <section className="panel">
      <div className="table">
        <div className="table-row table-head">
          {headers.map((h) => (
            <span key={h}>{h}</span>
          ))}
        </div>
        {rows.map((row, index) => (
          <div className="table-row" key={`${row[0]}-${index}`}>
            {row.map((cell, i) => (
              <span key={i}>{cell}</span>
            ))}
          </div>
        ))}
        {!rows.length && <p className="empty">{empty}</p>}
      </div>
    </section>
  );
}
