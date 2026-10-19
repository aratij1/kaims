// Narrow Node interfaces used only by opt-in local fixture tests.
declare module "node:fs" {
  export function readFileSync(path: string, encoding: "utf8"): string;
}
declare module "node:process" {
  export const env: Record<string, string | undefined>;
}
