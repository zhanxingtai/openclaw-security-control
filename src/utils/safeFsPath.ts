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
 *
 * Both the candidate path AND the roots are unwound through realpath before
 * comparison: a root whose textual form differs from its filesystem form —
 * macOS `/var` → `/private/var`, or the Windows 8.3 short-name temp dirs
 * GitHub Actions uses (`C:\Users\RUNNER~1\...`) — would otherwise make every
 * legitimate path under it look like an escape.
 */

import { realpathSync } from 'fs';
import { homedir } from 'os';
import path from 'path';

const realpath = (p: string): string => (realpathSync.native ?? realpathSync)(p);

/**
 * realpath a path; when it does not exist yet (ENOENT), walk up to the
 * nearest existing ancestor, realpath that, and re-append the literal tail.
 * The tail consists of single path components collected on the way up, so a
 * `..` segment can never be reintroduced. Other errors (EACCES, ELOOP)
 * propagate — they can hide symlink races the operator cannot audit.
 */
function unwindSymlinks(absolute: string): string {
  try {
    return realpath(absolute);
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') throw err;
    let tail = '';
    let dir = absolute;
    for (;;) {
      const parent = path.dirname(dir);
      if (parent === dir) return absolute; // filesystem root missing: unreachable in practice
      tail = tail ? path.join(path.basename(dir), tail) : path.basename(dir);
      dir = parent;
      try {
        return path.join(realpath(dir), tail);
      } catch (err2) {
        if ((err2 as NodeJS.ErrnoException)?.code !== 'ENOENT') throw err2;
      }
    }
  }
}

/**
 * realpath an allowed root. A root that does not exist yet (e.g. a fresh
 * user's `~/.openclaw`) keeps its lexical form — walking up to an existing
 * ancestor here would silently widen the sandbox to that ancestor.
 */
function unwindRoot(root: string): string {
  try {
    return realpath(root);
  } catch {
    return root;
  }
}

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

  for (const root of allowedRoots) {
    const resolvedRoot = unwindRoot(path.resolve(root));
    let resolved: string;
    try {
      resolved = unwindSymlinks(absolute);
    } catch {
      // EACCES / ELOOP / other: refuse — these can hide symlink races.
      return undefined;
    }
    // Containment on resolved-vs-resolved: a symlink inside the root that
    // points at a real file outside it (e.g. ~/.openclaw/link -> /etc/shadow)
    // is unwound to its true location and fails the check exactly like the
    // /etc/shadow class of paths this gate exists to stop.
    const rel = path.relative(resolvedRoot, resolved);
    if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) {
      return resolved;
    }
  }
  return undefined;
}
