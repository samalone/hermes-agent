import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'vitest'

import { formatUuid, restampMachoUuids, stampMachoUuid, uuidV5 } from './set-macho-uuid.mjs'

const CPU_ARM64 = 0x0100000c
const CPU_X86_64 = 0x01000007
const STOCK_UUID = Buffer.from('4c4c442655553144a1648bf7eab320e6', 'hex')

/** A minimal thin Mach-O: header, one unrelated load command, then LC_UUID. */
function thinMacho(cputype, uuid = STOCK_UUID) {
  const buf = Buffer.alloc(32 + 16 + 24)
  buf.writeUInt32LE(0xfeedfacf, 0)
  buf.writeInt32LE(cputype, 4)
  buf.writeUInt32LE(2, 16) // ncmds
  buf.writeUInt32LE(16 + 24, 20) // sizeofcmds
  buf.writeUInt32LE(0x2a, 32) // LC_SOURCE_VERSION
  buf.writeUInt32LE(16, 36)
  buf.writeUInt32LE(0x1b, 48) // LC_UUID
  buf.writeUInt32LE(24, 52)
  uuid.copy(buf, 56)
  return buf
}

function fatMacho(slices) {
  const header = Buffer.alloc(8 + 20 * slices.length)
  header.writeUInt32BE(0xcafebabe, 0)
  header.writeUInt32BE(slices.length, 4)
  let offset = 4096
  const parts = []
  slices.forEach((slice, i) => {
    const entry = 8 + i * 20
    header.writeInt32BE(slice.readInt32LE(4), entry)
    header.writeUInt32BE(offset, entry + 8)
    header.writeUInt32BE(slice.length, entry + 12)
    parts.push({ offset, slice })
    offset += 4096
  })
  const buf = Buffer.alloc(offset)
  header.copy(buf, 0)
  for (const { offset: at, slice } of parts) {
    slice.copy(buf, at)
  }
  return buf
}

const uuidAt = (buf, at) => formatUuid(buf.subarray(at, at + 16))

test('uuidV5 matches the RFC 4122 reference vector', () => {
  // Python: uuid.uuid5(uuid.NAMESPACE_URL, "http://python.org/")
  assert.equal(formatUuid(uuidV5('http://python.org/')), '4C565F0D-3F5A-5890-B41B-20CF47701C5E')
})

test('restamps a thin arm64 launcher deterministically, away from the stock Electron UUID', () => {
  const a = thinMacho(CPU_ARM64)
  const [change] = restampMachoUuids(a, 'com.nousresearch.hermes')
  assert.equal(change.from, formatUuid(STOCK_UUID))
  assert.notEqual(change.to, change.from)
  assert.equal(uuidAt(a, 56), change.to)
  assert.equal(change.to[14], '5') // version 5

  const b = thinMacho(CPU_ARM64)
  restampMachoUuids(b, 'com.nousresearch.hermes')
  assert.deepEqual(a, b, 'same appId + arch must give the same UUID across rebuilds')

  const other = thinMacho(CPU_ARM64)
  restampMachoUuids(other, 'com.nousresearch.hermes.light')
  assert.notEqual(uuidAt(other, 56), change.to, 'a different appId must get a different UUID')
})

test('restamps every slice of a universal binary with a distinct UUID', () => {
  const fat = fatMacho([thinMacho(CPU_X86_64), thinMacho(CPU_ARM64)])
  const changes = restampMachoUuids(fat, 'com.nousresearch.hermes')
  assert.equal(changes.length, 2)
  assert.notEqual(changes[0].to, changes[1].to)
  assert.equal(uuidAt(fat, 4096 + 56), changes[0].to)
  assert.equal(uuidAt(fat, 8192 + 56), changes[1].to)
})

test('refuses non-Mach-O input and a missing appId', () => {
  assert.throws(() => restampMachoUuids(Buffer.alloc(64), 'com.nousresearch.hermes'), /not a 64-bit Mach-O/)
  assert.throws(() => restampMachoUuids(thinMacho(CPU_ARM64), undefined), /appId is required/)
})

const electronBin = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../node_modules/electron/dist/Electron.app/Contents/MacOS/Electron'
)

test.runIf(process.platform === 'darwin' && fs.existsSync(electronBin))(
  'restamps a copy of the real Electron launcher; dwarfdump agrees',
  async () => {
    const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'macho-uuid-')), 'Electron')
    fs.copyFileSync(electronBin, tmp)
    const [change] = await stampMachoUuid(tmp, 'com.nousresearch.hermes')
    const dump = execFileSync('dwarfdump', ['--uuid', tmp], { encoding: 'utf8' })
    assert.match(dump, new RegExp(`UUID: ${change.to} `))
    assert.doesNotMatch(dump, new RegExp(change.from))
  }
)
