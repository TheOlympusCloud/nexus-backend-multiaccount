import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {backendOfflineCargoConfig,backendSourceArchiveArgs} from '../backend-source-archive.mjs';
test('vendored offline source retains the exact x86 and ARM AES compiler flags', async () => {
  const flags = '[target.\'cfg(target_arch = "x86_64")\']\nrustflags = ["-Ctarget-feature=+aes,+ssse3"]\n\n[target.\'cfg(target_arch = "aarch64")\']\nrustflags = ["-Ctarget-feature=+aes"]\n';
  const vendor = '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "vendor"\n';
  assert.equal(backendOfflineCargoConfig(flags, vendor), flags.trimEnd() + '\n\n' + vendor);
  const script = await fs.readFile('scripts/build-backend.mjs', 'utf8');
  assert.match(script, /backendOfflineCargoConfig\(originalCargoConfig, config\)/);
});


test('corresponding-source archive preserves nested target source directories', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'backend-source-archive-'));
  try {
    const entries = ['source/.git/config', 'source/target/debug/binary', 'source/vendor/cc/src/target/apple.rs',
      'source/vendor/dependency/.git/reference', 'source/vendor/other/source/target/parser.rs',
      'source/vendor/other/source/.git/reference', 'source/crates/xodus/src/lib.rs', 'source/scripts/build-backend.mjs', 'source/scripts/backend-source-archive.mjs', 'recipe/source.json'];
    for (const name of entries) {
      await fs.mkdir(path.dirname(path.join(root, name)), { recursive: true });
      await fs.writeFile(path.join(root, name), 'synthetic source');
    }
    const archive = path.join(root, 'source.tar.xz');
    execFileSync('tar', backendSourceArchiveArgs(archive, root));
    const listing = execFileSync('tar', ['-tJf', archive], { encoding: 'utf8' }).split('\n');
    for (const name of entries.slice(2)) assert.ok(listing.includes(name), `Missing ${name}`);
    for (const name of entries.slice(0, 2)) assert.ok(!listing.includes(name), `Unexpected ${name}`);
    const build = await fs.readFile('scripts/build-backend.mjs', 'utf8');
    assert.match(build, /command\('tar', backendSourceArchiveArgs\(/);
    assert.match(build, /'clone', '--no-checkout', '--no-hardlinks', '--no-local'/);
    assert.match(build, /source.json/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
