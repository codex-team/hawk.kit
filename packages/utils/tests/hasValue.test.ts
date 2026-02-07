import { describe, it, expect } from 'vitest';
import { hasValue } from '../src/hasValue';

describe('hasValue', () => {
  it('returns false for undefined', () => {
    expect(hasValue(undefined)).toBe(false);
  });

  it('returns false for null', () => {
    expect(hasValue(null)).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(hasValue('')).toBe(false);
  });

  it('returns true for non-empty string', () => {
    expect(hasValue('x')).toBe(true);
  });

  it('returns true for number 0', () => {
    expect(hasValue(0)).toBe(true);
  });

  it('returns true for object', () => {
    expect(hasValue({})).toBe(true);
  });
});
