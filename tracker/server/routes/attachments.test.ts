/**
 * Unit tests for the attachment helpers hardened in the Batch 3 audit:
 *   - sanitizeFilename: strips unsafe chars + bounds length
 *   - contentDisposition: RFC 5987 filename* + ASCII fallback, header-injection safe
 */
import { describe, it, expect } from 'vitest';
import { sanitizeFilename, contentDisposition, MAX_FILENAME_LEN } from './attachments.ts';

describe('sanitizeFilename', () => {
  it('replaces unsafe characters with underscores', () => {
    expect(sanitizeFilename('my report (final).pdf')).toBe('my_report__final_.pdf');
  });

  it('bounds the length to MAX_FILENAME_LEN', () => {
    const long = 'a'.repeat(MAX_FILENAME_LEN + 50) + '.pdf';
    expect(sanitizeFilename(long).length).toBe(MAX_FILENAME_LEN);
  });

  it('replaces all-unsafe characters but keeps a placeholder length', () => {
    expect(sanitizeFilename('***')).toBe('___');
  });

  it('falls back to "attachment" for an empty name', () => {
    expect(sanitizeFilename('')).toBe('attachment');
  });
});

describe('contentDisposition', () => {
  it('emits both an ASCII filename and an RFC 5987 filename*', () => {
    const cd = contentDisposition('report.pdf');
    expect(cd).toContain('filename="report.pdf"');
    expect(cd).toContain("filename*=UTF-8''report.pdf");
  });

  it('percent-encodes non-ASCII names in the filename* form', () => {
    const cd = contentDisposition('résumé.pdf');
    expect(cd).toContain("filename*=UTF-8''r%C3%A9sum%C3%A9.pdf");
  });

  it('is header-injection safe (strips CR/LF and quotes from the ASCII fallback)', () => {
    const cd = contentDisposition('evil"\r\nSet-Cookie: x=1.pdf');
    expect(cd).not.toContain('\r');
    expect(cd).not.toContain('\n');
    // The raw double-quote must not survive into the ASCII fallback token.
    expect(cd).not.toContain('evil"');
  });
});
