/**
 * Path-safety helpers for user-supplied filesystem paths.
 *
 * Plugin code resolves several paths from config (policyPath, logPath,
 * ndjsonPath, watchPaths, skillPaths, mcpPaths, …). Without a guard these
 * accept arbitrary locations — a hostile or misconfigured policy file path
 * like `/etc/shadow` would otherwise be read and parsed without complaint.
 *
 * `safeFsPath` resolves the path through realpath so symlinks are unwound,
 * then verifies the result lives under one of the configured allowed roots
 * (typically `~/.openclaw/`). It returns the resolved path on success or
 * `undefined` if the path escapes the sandbox. Callers MUST treat
 * `undefined` as "reject the input" — never fall through to the raw value.
 */

import { realpathSync } from 'fs';
import { homedir } from 'os';
import path from 'path';

export function safeFsPath(
  value: string | undefined,
  allowedRoots: string[] = [path.join(homedir(), '.openclaw')]
): string | undefined {
  if (!value || typeof value !== 'string') return undefined;
  // Expand a single leading `~` (do not chain: `~~/foo` is literal).
  const expanded = value === '~'
    ? homedir()
    : value.startsWith('~/') || value.startsWith('~' + path.sep)
      ? path.join(homedir(), value.slice(2))
      : value;
  const absolute = path.isAbsolute(expanded) ? expanded : path.resolve(expanded);

  // Verify the path is under at least one allowed root. Use path.relative to
  // detect escapes (`..` results in a leading `..` segment).
  for (const root of allowedRoots) {
    const resolvedRoot = path.resolve(root);
    const rel = path.relative(resolvedRoot, absolute);
    if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) {
      // Resolve symlinks for a tight check. We previously returned the
      // un-resolved absolute path on realpathSync failure which let a
      // hostile filesystem that already had a dangling symlink under
      // ~/.openclaw sneak through. Distinguish:
      //   - ENOENT (file genuinely does not exist yet): return the absolute
      //     path so callers downstream can surface "file not found" instead
      //     of a misleading "outside sandbox" error.
      //   - EACCES / ELOOP / other: refuse — these can hide symlink
      //     races the operator cannot audit.
      try {
        const fn = realpathSync.native ?? realpathSync;
        const resolved = fn(absolute);
        // Re-verify containment AFTER unwinding symlinks: a symlink inside
        // the root that points at a real file outside it (e.g. ~/.openclaw/
        // link -> /etc/shadow) lexically passes the check above, and the old
        // code returned the out-of-root realpath — the gate leaked exactly
        // the /etc/shadow class of paths it exists to stop.
        const resolvedRel = path.relative(resolvedRoot, resolved);
        if (resolvedRel === '' || (!resolvedRel.startsWith('..') && !path.isAbsolute(resolvedRel))) {
          return resolved;
        }
        return undefined;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if (code === 'ENOENT') {
          return absolute;
        }
        return undefined;
      }
    }
  }
  return undefined;
}