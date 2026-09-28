// set-macho-uuid.mjs — give the macOS launcher its own Mach-O LC_UUID.
//
// WHY THIS EXISTS (#81563, #113494, #95598)
// -----------------------------------------
// The packed Hermes.app launcher is the stock Electron executable renamed, so
// its LC_UUID is byte-identical to node_modules/electron/dist/Electron.app and
// to every other unmodified app on the same Electron release. macOS Local
// Network privacy (nehelper) resolves the process by that UUID:
//
//   LocalNetwork: found bundle id com.github.Electron by UUID 4C4C4426-…
//   nehelper: Local network allowed by preference for Electron (com.github.Electron)
//
// so Hermes is never evaluated (or prompted for) as itself, and the kernel
// keeps dropping its LAN connections (reason: NECP → ERR_ADDRESS_UNREACHABLE,
// EHOSTUNREACH). Re-signing does not help: the UUID is the key, not the Team ID.
//
// Stamping a UUID derived from the appId (plus the slice's CPU type) breaks
// the collision. It is deterministic, so every rebuild — `hermes update`,
// `npm run pack` — produces the same UUID and a user's Local Network grant
// survives updates.
//
// HOW IT RUNS
// -----------
// From the afterExtract hook (scripts/after-extract.mjs), on the pristine
// Electron.app before electron-builder renames it and before osx-sign, so the
// normal signing pass covers the edited bytes. Handles thin and fat (universal)
// 64-bit Mach-O files; each slice gets its own UUID.

import crypto from 'node:crypto'
import fs from 'node:fs/promises'

const MH_MAGIC_64 = 0xfeedfacf
const FAT_MAGIC = 0xcafebabe
const FAT_MAGIC_64 = 0xcafebabf
const LC_UUID = 0x1b
const MACH_HEADER_64_SIZE = 32

// RFC 4122 URL namespace, as bytes.
const NAMESPACE_URL = Buffer.from('6ba7b8119dad11d180b400c04fd430c8', 'hex')

/** RFC 4122 version-5 (SHA-1, name-based) UUID as 16 raw bytes. */
export function uuidV5(name, namespace = NAMESPACE_URL) {
  const hash = crypto.createHash('sha1').update(namespace).update(name, 'utf8').digest()
  const bytes = Buffer.from(hash.subarray(0, 16))
  bytes[6] = (bytes[6] & 0x0f) | 0x50
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  return bytes
}

export function formatUuid(bytes) {
  const hex = Buffer.from(bytes).toString('hex').toUpperCase()
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/** Byte offsets of every 64-bit Mach-O slice in `buf`, with its CPU type. */
function machoSlices(buf) {
  const beMagic = buf.readUInt32BE(0)
  if (beMagic === FAT_MAGIC || beMagic === FAT_MAGIC_64) {
    const count = buf.readUInt32BE(4)
    const entrySize = beMagic === FAT_MAGIC_64 ? 32 : 20
    const slices = []
    for (let i = 0; i < count; i++) {
      const entry = 8 + i * entrySize
      const cputype = buf.readInt32BE(entry)
      const offset = beMagic === FAT_MAGIC_64 ? Number(buf.readBigUInt64BE(entry + 8)) : buf.readUInt32BE(entry + 8)
      slices.push({ offset, cputype })
    }
    return slices
  }
  if (buf.readUInt32LE(0) === MH_MAGIC_64) {
    return [{ offset: 0, cputype: buf.readInt32LE(4) }]
  }
  throw new Error('not a 64-bit Mach-O or fat binary')
}

/** Offset of the 16 UUID bytes in the slice at `base`, or null without LC_UUID. */
function uuidOffset(buf, base) {
  if (buf.readUInt32LE(base) !== MH_MAGIC_64) {
    throw new Error(`slice at ${base} is not a 64-bit little-endian Mach-O`)
  }
  const ncmds = buf.readUInt32LE(base + 16)
  let cmd = base + MACH_HEADER_64_SIZE
  for (let i = 0; i < ncmds; i++) {
    const type = buf.readUInt32LE(cmd)
    const size = buf.readUInt32LE(cmd + 4)
    if (type === LC_UUID) {
      return cmd + 8
    }
    if (size < 8) {
      throw new Error(`malformed load command at ${cmd}`)
    }
    cmd += size
  }
  return null
}

/**
 * Rewrite the LC_UUID of every slice in `buf` (in place) to uuidV5(`${appId}:${cputype}`).
 * Returns one { cputype, from, to } record per slice that had an LC_UUID.
 */
export function restampMachoUuids(buf, appId) {
  if (!appId) {
    throw new Error('appId is required')
  }
  const changes = []
  for (const { offset, cputype } of machoSlices(buf)) {
    const at = uuidOffset(buf, offset)
    if (at === null) {
      continue
    }
    const from = formatUuid(buf.subarray(at, at + 16))
    const next = uuidV5(`${appId}:${cputype}`)
    next.copy(buf, at)
    changes.push({ cputype, from, to: formatUuid(next) })
  }
  return changes
}

/** Restamp the Mach-O file at `file` in place. */
export async function stampMachoUuid(file, appId) {
  const buf = await fs.readFile(file)
  const changes = restampMachoUuids(buf, appId)
  if (changes.length === 0) {
    throw new Error(`${file} has no LC_UUID load command`)
  }
  await fs.writeFile(file, buf)
  return changes
}
