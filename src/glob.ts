/** Converts a `*` / `?` wildcard pattern into an anchored regular expression. */
export function globToRegExp(glob: string): RegExp {
  const source = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${source}$`);
}

/** What a tool rule needs from its pattern: does this tool name match. */
export interface NameMatcher {
  test(name: string): boolean;
}

/**
 * One spelling for the naming styles a server can pick for the same tool: `deleteFile`, `DeleteFile`, `delete-file`,
 * `DELETE_FILE` and `delete.file` all become `delete_file`. Every step is a single linear pass (tool names come from
 * the server, so no pattern here may backtrack). Wildcards pass through, so the same fold works on a glob.
 */
export function foldToolName(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2') // deleteFile -> delete_File
    .replace(/([A-Z])(?=[A-Z][a-z])/g, '$1_') // HTTPRequest -> HTTP_Request
    .replace(/[\s._:/-]+/g, '_')
    .toLowerCase();
}

/**
 * Matcher for a restrictive pattern (a deny or ask rule, a taint source or sink): it matches the name as written OR in
 * its folded form, so `delete_*` also catches `deleteFile`, and nothing the exact pattern matched is lost. Names with
 * no boundary at all (`DELETEFILE`, `deletefile`) cannot be split and still need a pattern such as `delete*`.
 * Allow rules keep the exact matcher: widening them would quietly open an allow-list on upgrade.
 */
export function restrictiveToolMatcher(glob: string): NameMatcher {
  const exact = globToRegExp(glob);
  const folded = globToRegExp(foldToolName(glob));
  return { test: (name: string) => exact.test(name) || folded.test(foldToolName(name)) };
}
