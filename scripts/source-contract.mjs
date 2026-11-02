import fs from 'node:fs';
import {createHash} from 'node:crypto';
export function validateBuildConfig(config) {
  if (config?.schema !== 1 || config.repository !== 'domsvoboda/nexus-backend' ||
      !/^\d+\.\d+\.\d+$/.test(config.version ?? '') || !/^\d+\.\d+\.\d+$/.test(config.rust ?? '') ||
      !/^[a-f0-9]{64}$/.test(config.cargoLockSha256 ?? '') || !/^linux-run-v\d+$/.test(config.compatibility ?? '') ||
      config.authUi !== 'electron' || !/^[a-f0-9]{40}$/.test(config.upstream?.commit ?? '')) throw Error('Invalid backend build configuration');
  return config;
}
export function readBuildConfig(root) {
  const config = validateBuildConfig(JSON.parse(fs.readFileSync(new URL('build-config.json', root))));
  const digest = createHash('sha256').update(fs.readFileSync(new URL('Cargo.lock', root))).digest('hex');
  if (digest !== config.cargoLockSha256) throw Error('Backend Cargo.lock mismatch');
  return config;
}
