/**
 * Safely extract a value from a potentially nested object.
 * Returns fallback if getter throws or returns undefined.
 */
export function safeExtract<T>(getter: () => T | undefined, fallback?: T): T | undefined {
  try {
    const value = getter();
    return value !== undefined ? value : fallback;
  } catch {
    return fallback;
  }
}

export function safeExtractArray<T>(getter: () => T[] | undefined, fallback: T[] = []): T[] {
  const value = safeExtract(getter, fallback);
  return Array.isArray(value) ? value : fallback;
}
