/**
 * Returns true if specified value is not undefined, null and empty string.
 * @param v - Value to check.
 * @returns True when `v` is defined, not null, and not empty string.
 */
export function hasValue(v: unknown): boolean {
  return v !== undefined && v !== null && v !== '';
}
