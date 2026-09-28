import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { test, vi } from 'vitest'

const stampExeIdentity = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
vi.mock('./set-exe-identity.mjs', () => ({ stampExeIdentity }))

const { default: afterExtract } = await import('./after-extract.mjs')

const require = createRequire(import.meta.url)
const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
// The builder config is electron-builder.config.cjs (package.json carries no `build` block).
const builderConfig = require(path.join(desktopRoot, 'electron-builder.config.cjs'))

// #105629: the identity stamp must run BEFORE electron-builder's ASAR-integrity
// rewrite of the exe (beforeCopyExtraFiles), i.e. from afterExtract, never from
// afterPack — rcedit cannot commit changes to the resedit-rewritten PE. And the
// fix must keep the integrity check on (no disableAsarIntegrity workaround).
test('the exe identity stamp is wired to afterExtract with ASAR integrity kept on', () => {
  assert.equal(builderConfig.afterExtract, 'scripts/after-extract.mjs')
  assert.equal(builderConfig.disableAsarIntegrity, undefined)
})

test('stamps the stock electron.exe on win32 only, before it is renamed to Hermes.exe', async () => {
  stampExeIdentity.mockClear()
  const appOutDir = path.join('tmp', 'win-unpacked')

  await afterExtract({
    appOutDir,
    electronPlatformName: 'win32',
    packager: { appInfo: { productFilename: 'Hermes' } }
  })
  assert.deepEqual(stampExeIdentity.mock.calls, [[path.join(appOutDir, 'electron.exe'), desktopRoot]])

  stampExeIdentity.mockClear()
  await afterExtract({
    appOutDir: path.join('tmp', 'linux-unpacked'),
    electronPlatformName: 'linux',
    packager: { appInfo: { productFilename: 'Hermes' } }
  })
  assert.equal(stampExeIdentity.mock.calls.length, 0)
})

// #81563: on darwin the hook restamps the pristine Electron.app launcher's
// LC_UUID (before the rename to Hermes.app and before osx-sign), and leaves
// the Windows exe stamp alone.
test('restamps the Electron.app launcher LC_UUID on darwin, seeded by the appId', async () => {
  stampExeIdentity.mockClear()
  const appOutDir = fs.mkdtempSync(path.join(os.tmpdir(), 'after-extract-mac-'))
  const macosDir = path.join(appOutDir, 'Electron.app', 'Contents', 'MacOS')
  fs.mkdirSync(macosDir, { recursive: true })
  const launcher = Buffer.alloc(32 + 24)
  launcher.writeUInt32LE(0xfeedfacf, 0)
  launcher.writeInt32LE(0x0100000c, 4) // arm64
  launcher.writeUInt32LE(1, 16) // ncmds
  launcher.writeUInt32LE(0x1b, 32) // LC_UUID
  launcher.writeUInt32LE(24, 36)
  Buffer.from('4c4c442655553144a1648bf7eab320e6', 'hex').copy(launcher, 40)
  fs.writeFileSync(path.join(macosDir, 'Electron'), launcher)

  await afterExtract({
    appOutDir,
    electronPlatformName: 'darwin',
    packager: { appInfo: { id: 'com.nousresearch.hermes', productFilename: 'Hermes' } }
  })

  const stamped = fs.readFileSync(path.join(macosDir, 'Electron')).subarray(40, 56).toString('hex')
  assert.notEqual(stamped, '4c4c442655553144a1648bf7eab320e6')
  assert.equal(stampExeIdentity.mock.calls.length, 0)
})

test('a darwin stamp failure warns instead of failing the build', async () => {
  const appOutDir = fs.mkdtempSync(path.join(os.tmpdir(), 'after-extract-empty-'))
  await afterExtract({
    appOutDir,
    electronPlatformName: 'darwin',
    packager: { appInfo: { id: 'com.nousresearch.hermes' } }
  })
})
