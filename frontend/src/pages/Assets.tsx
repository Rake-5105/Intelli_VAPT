/** Asset inventory page. */
import { Table } from "../components/Table";
import type { Asset } from "../types";

type AssetsProps = {
  assets: Asset[];
  onBack?: () => void;
};

export function Assets({ assets }: AssetsProps) {
  return (
    <>
      <Table
        headers={["Asset", "IP", "HTTP", "Technologies", "Criticality"]}
        rows={assets.map((a) => [
          a.hostname,
          a.ip,
          a.http_status?.toString() || "-",
          a.technologies,
          a.criticality,
        ])}
        empty="No assets have been discovered for this project."
      />
    </>
  );
}
