/* tslint:disable */
/* eslint-disable */

export class PrivacerResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    replacements(): number;
    text(): string;
}

/**
 * Filter sensitive data from text (with entropy detection enabled by default)
 */
export function filter(text: string, enable_entropy: boolean): PrivacerResult;

/**
 * Check if text contains sensitive data (returns match count)
 */
export function scan(text: string, enable_entropy: boolean): number;
