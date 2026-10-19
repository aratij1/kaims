/** Call only with a successfully loaded, authoritative application list. */
export function availableApplication(current: string, options: string[]): string {
  const selected = current.trim().toLowerCase();
  return options.find((name) => name.toLowerCase() === selected)
    || options.find((name) => name.toLowerCase() === "kaims")
    || options[0] || "";
}
