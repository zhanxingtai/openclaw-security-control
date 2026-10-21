import { readFileSync } from 'fs';
import { hostname } from 'os';

export function getHostId(): string | undefined {
  return process.env.HOSTNAME || process.env.HOST || hostname() || undefined;
}

export function getContainerId(): string | undefined {
  try {
    const cgroup = readFileSync('/proc/self/cgroup', 'utf8');
    const lines = cgroup.trim().split('\n');
    for (const line of lines) {
      const parts = line.split(':');
      if (parts.length === 3) {
        const lastSegment = parts[2].split('/').pop();
        if (lastSegment && lastSegment.length >= 12) {
          return lastSegment.slice(0, 12);
        }
      }
    }
  } catch {
    // Not in container or permission denied
  }
  return process.env.CONTAINER_ID || undefined;
}

export function getPodName(): string | undefined {
  return process.env.POD_NAME || undefined;
}

export function getNamespace(): string | undefined {
  return process.env.NAMESPACE || undefined;
}
