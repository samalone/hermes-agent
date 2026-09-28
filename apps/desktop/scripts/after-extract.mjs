/**
 * after-extract.mjs — electron-builder afterExtract hook.
 *
 * Stamps the Hermes icon + identity onto the unpacked Windows Electron binary
 * before electron-builder renames it and injects the ASAR integrity resource.
 *
 * WHY afterExtract and not afterPack (#105629): with ASAR integrity on (the
 * default) electron-builder's `beforeCopyExtraFiles` rebuilds the whole PE in
 * memory with resedit to push the ELECTRONASAR resource. rcedit cannot commit
 * changes to that rewritten PE ("Fatal error: Unable to commit changes"),
 * deterministically, on every build. afterExtract fires on the pristine
 * electron.exe, before the rename and the integrity rewrite, and resedit then
 * carries the stamped resources through — so the exe keeps both its identity
 * and its integrity checksum. Disabling `disableAsarIntegrity` would also
 * "fix" it, at the cost of the integrity check on every Windows build.
 *
 * Windows: rcedit edits PE resources, irrelevant on macOS/Linux where the app
 * identity comes from the bundle Info.plist / desktop entry. Best-effort: a
 * stamp failure must never fail an otherwise-good build (worst case is the
 * stock icon, not a broken app), so we log and resolve rather than throw.
 *
 * macOS: restamps the launcher's Mach-O LC_UUID (scripts/set-macho-uuid.mjs)
 * so Local Network privacy stops resolving Hermes as com.github.Electron
 * (#81563). Done here for the same reason: the Electron.app is still pristine
 * and unsigned, so osx-sign's normal pass covers the edit. Also best-effort —
 * without it the app still runs; it just can't reach LAN hosts on macOS 15+.
 *
 * electron-builder passes a context with:
 *   - electronPlatformName: 'win32' | 'darwin' | 'linux'
 *   - appOutDir:            the unpacked Electron directory
 *   - packager.config.electronBranding.projectName: source binary basename
 *   - packager.appInfo.id:  the appId (macOS UUID seed)
 */

import fs from 'node:fs/promises'
import path from 'node:path'

import { stampExeIdentity } from './set-exe-identity.mjs'
import { stampMachoUuid } from './set-macho-uuid.mjs'

/** The single executable in <appOutDir>/<Name>.app/Contents/MacOS, pre-rename. */
async function macLauncher(appOutDir) {
  const apps = (await fs.readdir(appOutDir)).filter(name => name.endsWith('.app'))
  if (apps.length !== 1) {
    throw new Error(`expected one .app in ${appOutDir}, found ${apps.length}`)
  }
  const macosDir = path.join(appOutDir, apps[0], 'Contents', 'MacOS')
  const entries = await fs.readdir(macosDir)
  if (entries.length !== 1) {
    throw new Error(`expected one executable in ${macosDir}, found ${entries.length}`)
  }
  return path.join(macosDir, entries[0])
}

async function stampMacLauncherUuid(context) {
  const appId = context.packager?.appInfo?.id
  try {
    const launcher = await macLauncher(context.appOutDir)
    for (const { from, to } of await stampMachoUuid(launcher, appId)) {
      console.log(`[after-extract] ${path.basename(launcher)} LC_UUID ${from} -> ${to}`)
    }
  } catch (err) {
    console.warn(`[after-extract] LC_UUID stamp failed (${err.message}); macOS Local Network privacy will treat the app as com.github.Electron`)
  }
}

export default async function afterExtract(context) {
  if (context.electronPlatformName === 'darwin') {
    await stampMacLauncherUuid(context)
    return
  }
  if (context.electronPlatformName !== 'win32') {
    return
  }

  const projectName = context.packager?.config?.electronBranding?.projectName || 'electron'
  const exe = path.join(context.appOutDir, `${projectName}.exe`)
  const desktopRoot = path.resolve(import.meta.dirname, '..')

  try {
    await stampExeIdentity(exe, desktopRoot)
  } catch (err) {
    // Never fail the build over a cosmetic stamp.
    console.warn(`[after-extract] exe identity stamp failed (${err.message}); ${projectName}.exe keeps the stock Electron icon`)
  }
}
