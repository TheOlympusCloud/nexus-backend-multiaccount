// Only synthetic unit/protocol fixtures. Never start the service or a real account.
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {availableParallelism} from 'node:os';
import {execFileSync} from 'node:child_process';
import {readBuildConfig} from './source-contract.mjs';
const root = new URL('../', import.meta.url);
const config = readBuildConfig(root);
const offline = process.argv.includes('--offline') ? ['--offline'] : [];
const plan = JSON.parse(fs.readFileSync(new URL('test-plan.json', import.meta.url)));
const env = {...process.env, CARGO_BUILD_JOBS:process.env.CARGO_BUILD_JOBS ?? String(availableParallelism())};
const run = (cmd,args,capture=false) => execFileSync(cmd,args,{cwd:fileURLToPath(root),env,stdio:capture?'pipe':'inherit',encoding:'utf8',maxBuffer:32*1024*1024});
if (!run('rustc',['--version'],true).startsWith(`rustc ${config.rust} `)) throw Error('Use the pinned Rust toolchain');
for (const args of plan) run('cargo',['test','--locked',...offline,'--no-default-features',...args]);
run('python3',['scripts/keyring-textual-roundtrip.test.py']);
