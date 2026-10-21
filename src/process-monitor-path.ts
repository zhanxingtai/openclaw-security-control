import { fileURLToPath } from 'url';
import fs from 'fs';
import path from 'path';

/**
 * Locate the embedded Python process monitor script at runtime.
 *
 * Supports several layouts:
 *   1. install bundle (new): install/application/utils/.. -> install/system/process_monitor.py
 *   2. install bundle (old): install/dist/utils/.. -> install/monitor/process_monitor.py
 *   3. npm package:          dist/utils/.. -> dist/monitor/process_monitor.py
 *   4. development:          dist/utils/.. -> src/monitor/process_monitor.py
 */
export function getProcessMonitorPath(): string {
  const currentFile = fileURLToPath(import.meta.url);
  const currentDir = path.dirname(currentFile);

  const candidates = [
    // New install bundle layout: install/application/utils -> install/system
    path.resolve(currentDir, '..', 'system', 'process_monitor.py'),
    // New install bundle layout from a nested utils dir
    path.resolve(currentDir, '..', '..', 'system', 'process_monitor.py'),
    // npm package / development layout: dist/utils -> dist/monitor
    path.resolve(currentDir, '..', 'monitor', 'process_monitor.py'),
    // Old install bundle layout: install/dist/utils -> install/monitor
    path.resolve(currentDir, '..', '..', 'monitor', 'process_monitor.py'),
    // Development fallback from dist/utils
    path.resolve(currentDir, '..', '..', 'src', 'monitor', 'process_monitor.py'),
    // Fallback relative to cwd
    path.resolve(process.cwd(), 'src', 'monitor', 'process_monitor.py'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    `Could not locate process_monitor.py. Searched:\n${candidates.join('\n')}`
  );
}
