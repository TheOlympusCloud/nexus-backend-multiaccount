// Build one pinned backend candidate. Never starts auth, a service or a game.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { availableParallelism } from 'node:os';
import { validateBuildConfig } from './source-contract.mjs';
import { backendOfflineCargoConfig, backendSourceArchiveArgs } from './backend-source-archive.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
const option = (name, fallback) => { const i = args.indexOf(name); return i < 0 ? fallback : args[i + 1]; };
const work = path.resolve(option('--work', 'backend-build'));
const output = path.resolve(option('--output', 'backend-release'));
const target = path.resolve(option('--target-dir', path.join(work, 'target')));
const lockBytes = await fs.readFile(path.join(root, 'build-config.json'));
const lock = JSON.parse(lockBytes);
const authUi = 'electron';
const features = ['--no-default-features'];
const archSuffix = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
if (process.platform !== 'linux' || !archSuffix) throw Error('Build the backend on Linux x86_64 or aarch64');
const sha = (data, algorithm = 'sha256') => createHash(algorithm).update(data).digest('hex');
validateBuildConfig(lock);
const git = args => execFileSync('git', args, {cwd:root, encoding:'utf8'}).trim();
const commit = git(['rev-parse', 'HEAD']);
if (!/^[a-f0-9]{40}$/.test(commit) || git(['status', '--porcelain', '--untracked-files=no']))
  throw Error('Build only a clean committed backend source');
if (sha(await fs.readFile(path.join(root, 'Cargo.lock'))) !== lock.cargoLockSha256) throw Error('Backend Cargo.lock mismatch');
await fs.mkdir(work);
await fs.mkdir(output);
const source = path.join(work, 'source');
const command = (tool, argv, capture = false) => execFileSync(tool, argv, {
  cwd: source, stdio: capture ? 'pipe' : 'inherit', encoding: 'utf8', maxBuffer: 20 * 1024 * 1024,
  env: { ...process.env, CARGO_TARGET_DIR: target, CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS ?? String(availableParallelism()) },
});
// Compile a fresh checkout of the exact commit, never untracked checkout files.
execFileSync('git', ['clone', '--no-checkout', '--no-hardlinks', '--no-local', root, source], {stdio:'inherit'});
command('git', ['checkout', '--detach', commit]);
if (command('git', ['rev-parse', 'HEAD'], true).trim() !== commit ||
    sha(await fs.readFile(path.join(source, 'build-config.json'))) !== sha(lockBytes)) throw Error('Backend source identity mismatch');
const offline = args.includes('--offline') ? ['--offline'] : [];
const rustc = command('rustc', ['--version'], true).trim();
if (!rustc.startsWith(`rustc ${lock.rust} `)) throw Error(`Use the locked Rust toolchain ${lock.rust}`);
command(process.execPath, [path.join(source, 'scripts/test-backend.mjs'), ...offline]);
command('cargo', ['build', '--release', '--locked', ...offline, ...features, '-p', 'xodus-cli', '-p', 'xodus-service']);
const cli = path.join(target, 'release/xodus-cli');
for (const name of ['xodus-cli', 'xodus-service']) {
  const file = await fs.open(path.join(target, 'release', name), 'r');
  const header = Buffer.alloc(64);
  try { await file.read(header, 0, header.length, 0); } finally { await file.close(); }
  if (header.subarray(0,4).toString('hex') !== '7f454c46' || header[4] !== 2 || header[5] !== 1 || header.readUInt16LE(18) !== {x64:62,arm64:183}[process.arch])
    throw Error('Backend ELF architecture mismatch: ' + name);
}
const help = command(cli, ['--help'], true);
if (authUi === 'electron' && !help.includes('--external-webview-stdio')) throw Error('External sign-in capability missing');
if (authUi === 'electron' && /lib(?:gtk|webkit|soup|javascriptcore)/i.test(command('readelf', ['-d', cli], true))) throw Error('Headless CLI links a native webview library');
for (const name of ['account', 'login', 'logout', 'download', 'streaming', 'run', 'offline-pc', 'resolve-package', 'game-activity', 'achievements', 'social', 'keyring-unlock', 'keyring-create', 'keyring-session-stop']) {
  if (!new RegExp(`^\\s{2}${name}\\s{2,}`, 'm').test(help)) throw Error(`Backend lacks ${name}`);
}
if (!command(cli, ['run', '--help'], true).includes('--materialize-chain')) throw Error('Launch-chain support missing');
const launchHelp = command(cli, ['run', '--help'], true);
for (const flag of ['--license-cache', '--offline']) if (!launchHelp.includes(flag)) throw Error('Offline launch capability missing: ' + flag);
if (!command(cli, ['offline-pc', '--help'], true).includes('--license-cache')) throw Error('Offline revocation capability missing');
if (!command(cli, ['resolve-package', '--help'], true).includes('--include-dlc')) throw Error('Managed DLC selection capability missing');
const streamingHelp = command(cli, ['streaming', '--help'], true);
if (!streamingHelp.includes('Nexus capabilities: update-recovery-v1')) throw Error('Durable update recovery capability missing');
for (const flag of ['--progress-json', '--control-stdin', '--selected-content-id', '--download-limit-kib']) {
  if (!streamingHelp.includes(flag)) throw Error(`Structured download capability missing: ${flag}`);
}
// xodus-service has no --help parser; running it would access keychain/network.
const name = `xodus-nexus-backend-${lock.version}-linux-${archSuffix}`;
const bundle = path.join(work, name);
await fs.mkdir(bundle);
const files = {};
for (const file of ['xodus-cli', 'xodus-service', 'LICENSE']) {
  const origin = file === 'LICENSE' ? path.join(source, file) : path.join(target, 'release', file);
  await fs.copyFile(origin, path.join(bundle, file));
  if (file !== 'LICENSE') await fs.chmod(path.join(bundle, file), 0o755);
  files[file] = sha(await fs.readFile(origin));
}
command('tar', ['-cJf', path.join(output, `${name}.tar.xz`), '-C', work, name]);
// Include vendored registry/Git dependency sources and offline Cargo config,
// alongside patched upstream source, GPL license, recipe and build tooling.
const config = command('cargo', ['vendor', '--locked', ...offline, 'vendor'], true);
const originalCargoConfig = await fs.readFile(path.join(source, '.cargo/config.toml'), 'utf8').catch(error => {
  if (error.code === 'ENOENT') return '';
  throw error;
});
await fs.mkdir(path.join(source, '.cargo'), { recursive: true });
await fs.writeFile(path.join(source, '.cargo/config.toml'), backendOfflineCargoConfig(originalCargoConfig, config));
const recipe = path.join(work, 'recipe');
await fs.mkdir(recipe);
await fs.copyFile(path.join(root, 'build-config.json'), path.join(recipe, 'build-config.json'));
await fs.writeFile(path.join(recipe, 'source.json'), JSON.stringify({repository:lock.repository, commit}, null, 2)+'\n');
await fs.writeFile(path.join(recipe, 'BUILD.txt'), `Backend source and vendored dependencies.\nSource: ${lock.repository}@${commit}\nRust ${lock.rust}; cargo build --locked --offline --release ${features.join(' ')} -p xodus-cli -p xodus-service from source/.\nRun node scripts/test-backend.mjs --offline for account-free regressions.\nAuthentication UI: ${authUi}.\nNative dependencies and packaging: source/docs/BUILD.md.\nGPL-3.0; dependency licenses retained in vendor/.\n`);
command('tar', backendSourceArchiveArgs(path.join(output, `${name}-source.tar.xz`), work));
for (const archive of [`${name}.tar.xz`, `${name}-source.tar.xz`]) {
  await fs.writeFile(path.join(output, archive.replace('.tar.xz', '.sha512sum')), `${sha(await fs.readFile(path.join(output, archive)), 'sha512')}  ${archive}\n`);
}
const manifest = {
  schema: 2, sourceRepository: lock.repository, version: lock.version, commit, recipeSha256: sha(lockBytes), compatibility: lock.compatibility, authUi,
  platform: 'linux', arch: process.arch, archive: `${name}.tar.xz`,
  archiveSha512: sha(await fs.readFile(path.join(output, `${name}.tar.xz`)), 'sha512'), files,
  rustc, glibc: command('getconf', ['GNU_LIBC_VERSION'], true).trim(),
};
await fs.writeFile(path.join(output, `${name}.manifest.json`), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Built ${name}; source, binaries and SHA-512 provenance recorded. No account/service/game started.`);
