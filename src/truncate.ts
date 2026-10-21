export function truncateString(content: unknown, maxLen: number): string {
  if (content === null || content === undefined) {
    return '';
  }
  let s: string;
  try {
    s = typeof content === 'string' ? content : JSON.stringify(content);
  } catch {
    s = '[unserializable content]';
  }
  const max = Number.isFinite(maxLen) && maxLen > 0 ? Math.floor(maxLen) : 0;
  return s.length > max ? s.slice(0, max) + '...' : s;
}

export function computeContentLength(content: unknown): number {
  if (typeof content === 'string') {
    return content.length;
  }
  try {
    return JSON.stringify(content).length;
  } catch {
    return 0;
  }
}
