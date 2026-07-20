import { env } from "node:process";

// Assign a string ID to a plugin entry for use in SEMREL_SKIP_STEPS matching
export function stepId(name, suffix) {
  return suffix ? `${name}:${suffix}` : name;
}

// Map from plugin entry tuple to its step ID — keeps the step ID out of the
// options object that semantic-release passes to plugin lifecycle functions
const stepIds = new Map();

// Build a filter function that removes plugins whose stepId is in SEMREL_SKIP_STEPS
// Each pipe-separated segment is compared as an exact literal step ID
export function buildSkipFilter() {
  const skipPattern = env.SEMREL_SKIP_STEPS;
  if (!skipPattern) return () => true; // keep all
  const skipSet = new Set(skipPattern.split("|").filter(Boolean));
  return (entry) => {
    if (!Array.isArray(entry)) return true;
    const id = stepIds.get(entry);
    return !id || !skipSet.has(id);
  };
}

// Helper: create a plugin entry and register its step ID in the Map.
// Supports two call signatures:
//   withId(name, suffix, options?) — registers as name:suffix
//   withId(name, options?)        — registers as name (no suffix)
function withId(name, suffixOrOptions, options = {}) {
  const suffix =
    typeof suffixOrOptions === "string" ? suffixOrOptions : undefined;
  const opts =
    typeof suffixOrOptions === "object" && suffixOrOptions !== null
      ? suffixOrOptions
      : options;
  const entry = [name, opts];
  stepIds.set(entry, stepId(name, suffix));
  return entry;
}

export const allPlugins = [
  "@semantic-release/commit-analyzer",
  "@semantic-release/release-notes-generator",
  withId("@semantic-release/changelog"),
  withId("@semantic-release/exec", "build", { prepareCmd: "npm run build" }),
  withId("@semantic-release/npm"),
  withId("@semantic-release/git", {
    assets: ["CHANGELOG.md", "package.json", "package-lock.json"],
    message:
      "chore(release): ${nextRelease.version}\n\n${nextRelease.notes}\n\n[skip ci]",
  }),
  withId("@semantic-release/github"),
];

export default {
  branches: [
    "main",
    { name: "pre", channel: "pre", prerelease: "pre" },
    { name: "alpha", channel: "alpha", prerelease: "alpha" },
    { name: "beta", channel: "beta", prerelease: "beta" },
    { name: "rc", channel: "rc", prerelease: "rc" },
  ],
  tagFormat: "v${version}",
  get plugins() {
    return allPlugins.filter(buildSkipFilter());
  },
};
