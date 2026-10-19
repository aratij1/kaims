import { useNavigate } from "react-router-dom";
import { durableIncidentPath, type IncidentIdentitySource } from "./incidentNavigation";

/** Every incident entry point opens the same durable incident workspace. */
export function useOpenIncident() {
  const navigate = useNavigate();
  return (row: IncidentIdentitySource, _legacyTab?: string) => {
    void _legacyTab; // Legacy callers pass tabs; all entry points use the canonical route.
    const path = durableIncidentPath(row);
    if (path) navigate(path);
  };
}
