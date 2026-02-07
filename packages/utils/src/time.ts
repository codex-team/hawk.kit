/* eslint-disable @typescript-eslint/no-magic-numbers */
/**
 * Time intervals in ms
 */
export enum TimeMs {
  /**
   * One millisecond (1 ms).
   */
  Millisecond = 1,
  /**
   * One second in milliseconds.
   */
  Second = TimeMs.Millisecond * 1000,
  /**
   * One minute in milliseconds.
   */
  Minute = TimeMs.Second * 60,
  /**
   * One hour in milliseconds.
   */
  Hour = TimeMs.Minute * 60,
  /**
   * One day in milliseconds.
   */
  Day = TimeMs.Hour * 24,
  /**
   * One week in milliseconds.
   */
  Week = TimeMs.Day * 7
}
