export type PluginEntry = string | [string, Record<string, unknown>];

export function stepId(name: string, suffix?: string): string;
export function buildSkipFilter(): (entry: PluginEntry) => boolean;
export declare const allPlugins: PluginEntry[];

declare const config: {
  branches: (string | { name: string; channel: string; prerelease: string })[];
  tagFormat: string;
  readonly plugins: PluginEntry[];
};
export default config;
