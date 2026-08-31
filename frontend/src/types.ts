/** Shared type definitions for IntelliVAPT frontend. */

export type User = {
  name: string;
  email: string;
  role: string;
};

export type Project = {
  id: string;
  name: string;
  client: string;
  status: string;
  targets: number;
  scans: number;
  description: string;
};

export type Target = {
  id: string;
  value: string;
  type: string;
  excluded: boolean;
};

export type Asset = {
  id: string;
  hostname: string;
  ip: string;
  http_status: number | null;
  title: string;
  technologies: string;
  criticality: string;
};

export type Finding = {
  id: string;
  title: string;
  endpoint: string;
  scanner: string;
  severity: string;
  cvss_score: number;
  cwe?: string;
  cve?: string;
  status: string;
  owasp_category: string;
  remediation: string;
};

export type ScanState = {
  id: string;
  progress: number;
  status: string;
};

export type GraphNode = {
  id: string;
  label: string;
  type: string;
};

export type GraphEdge = {
  source: string;
  target: string;
};

export type Surface = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

export type View =
  | "overview"
  | "projects"
  | "surface"
  | "assets"
  | "findings"
  | "remediation"
  | "reports";
