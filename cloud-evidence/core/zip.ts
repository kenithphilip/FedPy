/**
 * Dependency-free, store-only (uncompressed) ZIP writer + XML escaping.
 *
 * Both `.xlsx` (SpreadsheetML) and `.docx` (WordprocessingML) are ZIP containers
 * of XML parts. Rather than pull a heavyweight office-document or zip dependency
 * into a read-only evidence collector, we emit the container ourselves with a
 * minimal store-only ZIP (method 0, no compression) using Node's `zlib.crc32`.
 *
 * Store-only keeps the implementation tiny and the output deterministic; office
 * files do not require compression to be valid. Shared by inventory-workbook.ts
 * (xlsx) and ssp-docx.ts (docx).
 */
import { crc32 } from 'node:zlib';

/** Escape a string for inclusion in XML text / attribute content. */
export function xmlEscape(v: string): string {
  return v
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Build a store-only (uncompressed) ZIP from named buffers — valid for .xlsx/.docx. */
export function zipStore(files: Array<{ name: string; data: Buffer }>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const cr = crc32(f.data) >>> 0;
    const size = f.data.length;
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0); // local file header sig
    local.writeUInt16LE(20, 4);          // version needed
    local.writeUInt16LE(0, 6);           // flags
    local.writeUInt16LE(0, 8);           // method 0 = store
    local.writeUInt16LE(0, 10);          // mod time
    local.writeUInt16LE(0x21, 12);       // mod date (1980-01-01)
    local.writeUInt32LE(cr, 14);         // crc32
    local.writeUInt32LE(size, 18);       // compressed size
    local.writeUInt32LE(size, 22);       // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);          // extra len
    nameBuf.copy(local, 30);
    locals.push(local, f.data);

    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0); // central dir sig
    central.writeUInt16LE(20, 4);         // version made by
    central.writeUInt16LE(20, 6);         // version needed
    central.writeUInt16LE(0, 8);          // flags
    central.writeUInt16LE(0, 10);         // method
    central.writeUInt16LE(0, 12);         // mod time
    central.writeUInt16LE(0x21, 14);      // mod date
    central.writeUInt32LE(cr, 16);
    central.writeUInt32LE(size, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30);         // extra len
    central.writeUInt16LE(0, 32);         // comment len
    central.writeUInt16LE(0, 34);         // disk #
    central.writeUInt16LE(0, 36);         // internal attrs
    central.writeUInt32LE(0, 38);         // external attrs
    central.writeUInt32LE(offset, 42);    // local header offset
    nameBuf.copy(central, 46);
    centrals.push(central);
    offset += local.length + f.data.length;
  }
  const centralStart = offset;
  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);          // EOCD sig
  eocd.writeUInt16LE(0, 4);                    // disk #
  eocd.writeUInt16LE(0, 6);                    // disk w/ central dir
  eocd.writeUInt16LE(files.length, 8);         // entries on disk
  eocd.writeUInt16LE(files.length, 10);        // total entries
  eocd.writeUInt32LE(centralBuf.length, 12);   // central dir size
  eocd.writeUInt32LE(centralStart, 16);        // central dir offset
  eocd.writeUInt16LE(0, 20);                   // comment len
  return Buffer.concat([...locals, centralBuf, eocd]);
}
