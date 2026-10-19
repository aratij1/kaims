import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const frontendRoot = join(repositoryRoot, "frontend", "react");
const failures = [];
const notes = [];

function source(path) {
  const absolute = join(repositoryRoot, path);
  if (!existsSync(absolute)) {
    failures.push(`missing required file: ${path}`);
    return "";
  }
  return readFileSync(absolute, "utf8");
}

function lineCount(path) {
  return source(path).split(/\r?\n/).length;
}

function walk(directory) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  });
}

if (!existsSync(frontendRoot)) failures.push("frontend/react must remain the canonical production frontend");

const navigation = source("frontend/react/src/app/navigation.ts");
for (const path of [
  "/incidents",
  "/alerts",
  "/approvals",
  "/applications",
  "/cloud-ops/resources",
  "/cloud-ops/cockpit",
  "/cloud-ops/connections",
  "/knowledge",
  "/audit",
  "/admin",
]) {
  if (!navigation.includes(`path: "${path}"`)) failures.push(`canonical navigation is missing ${path}`);
}

const router = source("frontend/react/src/app/router.tsx");
if (!router.includes('path: "/incidents/:incidentId"')) failures.push("the Incident Command dynamic route is not registered");
if (!router.includes("resilientLazy")) failures.push("route-level resilient lazy loading must remain enabled");

const uiDockerfile = source("deploy/docker/Dockerfile.ui");
if (!uiDockerfile.includes("frontend/react")) failures.push("the production UI image is not built from frontend/react");
if (uiDockerfile.includes("services/ui/react")) failures.push("the production UI image still owns the legacy services/ui/react frontend");

const legacyAppLines = lineCount("frontend/react/src/App.jsx");
if (legacyAppLines > 12_860) failures.push(`src/App.jsx grew beyond the migration budget (${legacyAppLines} > 12860 lines)`);
else notes.push(`legacy App.jsx migration budget: ${legacyAppLines}/12860 lines`);

const featureFiles = walk(join(frontendRoot, "src", "features"));
for (const file of featureFiles) {
  const extension = extname(file);
  const path = relative(repositoryRoot, file).replaceAll("\\", "/");
  if ([".jsx", ".js"].includes(extension)) failures.push(`new feature code must use TypeScript: ${path}`);
  if ([".ts", ".tsx"].includes(extension)) {
    const lines = readFileSync(file, "utf8").split(/\r?\n/).length;
    if (lines > 650) failures.push(`feature module exceeds 650-line ownership budget: ${path} (${lines})`);
  }
  if (statSync(file).size > 80 * 1024) failures.push(`feature asset exceeds 80 KiB source budget: ${path}`);
}

const routeOwnedFiles = [
  ...featureFiles,
  ...walk(join(frontendRoot, "src", "routes")),
];
for (const file of routeOwnedFiles) {
  if (![".ts", ".tsx", ".js", ".jsx"].includes(extname(file))) continue;
  const path = relative(repositoryRoot, file).replaceAll("\\", "/");
  const content = readFileSync(file, "utf8");
  if (/from\s+["'][^"']*appHelpers(?:\.jsx)?["']/.test(content)) {
    failures.push(`route-owned code may not import the legacy appHelpers runtime: ${path}`);
  }
}

const incidentCommand = source("frontend/react/src/features/incidents/IncidentCommand.tsx");
for (const phrase of ["Not recorded", "IncidentCommandWorkspaceSchema", "requestValidated", "isRcaGrounded"]) {
  if (!incidentCommand.includes(phrase)) failures.push(`Incident Command truth contract is missing: ${phrase}`);
}
// Network polling is legitimate; synthetic progress and stage setters are not.
if (/Math\.random|set(?:Progress|Stage|Journey)\s*\(/.test(incidentCommand)) failures.push("Incident Command may not fabricate progress or stages");

if (existsSync(join(repositoryRoot, "services", "ui", "react"))) notes.push("legacy services/ui/react remains present but is not referenced by the production UI Dockerfile");
if (existsSync(join(frontendRoot, "src", "app", "LegacyApplicationShell.tsx"))) notes.push("LegacyApplicationShell remains as a migration adapter; feature work is budgeted under src/features");

for (const note of notes) console.log(`ARCHITECTURE NOTE: ${note}`);
if (failures.length) {
  for (const failure of failures) console.error(`ARCHITECTURE ERROR: ${failure}`);
  process.exit(1);
}
console.log("Architecture budgets passed.");
