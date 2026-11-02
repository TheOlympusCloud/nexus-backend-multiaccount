// Manual promotion only: download and verify tested bytes, never rebuild.
import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { verifyManifest } from './artifact-manifest.mjs';
import { validateBuildConfig } from '../source-contract.mjs';
import { validateBackendProvenance } from './backend-provenance.mjs';
import { releaseNotesRef, assertApprovedReleaseNotes } from './release-notes-policy.mjs';
const kind = process.env.CANDIDATE_KIND, runId = process.env.CANDIDATE_RUN;
const repo = process.env.GITHUB_REPOSITORY;
if (process.env.GITHUB_REF !== 'refs/heads/main' || process.env.APPROVE_RELEASE !== 'true') throw Error('Explicit main-branch release authorization required');
if (kind !== 'backend' || !/^\d+$/.test(runId ?? '') || repo !== 'domsvoboda/nexus-backend') throw Error('Invalid promotion selection');
const command = (tool, args) => execFileSync(tool, args, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
const run = JSON.parse(command('gh', ['api', `repos/${repo}/actions/runs/${runId}`]));
const workflow = JSON.parse(command('gh', ['api', `repos/${repo}/actions/workflows/${run.workflow_id}`]));
const expectedWorkflow = kind === 'launcher' ? '.github/workflows/ci.yml' : `.github/workflows/${kind}.yml`;
if (run.conclusion !== 'success' || run.head_branch !== 'main' || !['push', 'workflow_dispatch'].includes(run.event) ||
    workflow.path !== expectedWorkflow || !/^[a-f0-9]{40}$/.test(run.head_sha ?? '')) throw Error('Not a successful main candidate build');
command('git', ['merge-base', '--is-ancestor', run.head_sha, 'HEAD']);
const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'nexus-promotion-'));
try {
  command('gh', ['run', 'download', runId, '--repo', repo, '--name', kind === 'launcher' ? 'launcher-candidate' : `nexus-${kind}`, '--dir', directory]);
  const manifest = await verifyManifest(directory, { kind, repository: repo, commit: run.head_sha, runId });
  const hash = createHash('sha256').update(await fs.readFile(path.join(directory, 'candidate.json'))).digest('hex');
  const approvals = JSON.parse(await fs.readFile('.github/release-validation.json', 'utf8'));
  const approval = approvals.schema === 1 && approvals.approvals?.find(item => item.kind === kind && item.runId === runId &&
    item.commit === run.head_sha && item.manifestSha256 === hash && item.approved === true && item.approvedBy === process.env.GITHUB_ACTOR &&
    typeof item.evidence === 'string' && item.evidence.trim().length > 0);
  if (!approval) throw Error('No recorded human validation for this exact artifact');
  const configBytes = command('git', ['show', `${run.head_sha}:build-config.json`]);
  const config = validateBuildConfig(JSON.parse(configBytes));
  const recipeHash = createHash('sha256').update(configBytes).digest('hex');
  const metadataFiles = manifest.files.filter(file => file.name.endsWith('.manifest.json'));
  if (metadataFiles.length === 0) throw Error('Backend metadata missing');
  for (const file of metadataFiles) {
    const metadata = JSON.parse(await fs.readFile(path.join(directory, file.name), 'utf8'));
    validateBackendProvenance(metadata, file.name, config, run.head_sha, recipeHash);
    const checksumFile = manifest.files.find(entry => entry.name === metadata.archive.replace('.tar.xz', '.sha512sum'));
    if (!checksumFile || (await fs.readFile(path.join(directory, checksumFile.name), 'utf8')).trim() !== `${metadata.archiveSha512}  ${metadata.archive}`)
      throw Error('Backend archive identity mismatch');
  }
  const tag = `backend-v${config.version}`;
  const notesPath = `.github/release-notes/${kind === 'runtime' ? 'runtime-signin-updates.md' : `${kind}-${kind === 'launcher' ? tag.slice(1) : tag.slice('backend-v'.length)}.md`}`;
  const notes = command('git', ['show', `${releaseNotesRef(kind, run.head_sha, approval)}:${notesPath}`]);
  assertApprovedReleaseNotes(notes, approval);
  // One new release per tag. Never edit an existing release or replace assets.
  const existing = JSON.parse(command('gh', ['api', '--paginate', '--slurp', `repos/${repo}/releases?per_page=100`]));
  if (existing.flat().some(item => item.tag_name === tag)) throw Error('Release already exists');
  const tags = JSON.parse(command('gh', ['api', '--paginate', '--slurp', `repos/${repo}/tags?per_page=100`]));
  if (tags.flat().some(item => item.name === tag)) throw Error('Tag already exists');
  command('gh', ['release', 'create', tag, '--repo', repo, '--target', run.head_sha,
    ...manifest.files.map(file => path.join(directory, file.name)), path.join(directory, 'candidate.json'),
    ...(kind === 'launcher' ? [] : ['--latest=false']),
    '--title', `Xodus Nexus ${kind} ${kind === 'backend' ? tag.slice('backend-v'.length) : tag}`, '--notes', notes]);
  console.log(`Promoted approved ${kind} candidate ${runId} as ${tag}; no rebuild performed.`);
} finally { await fs.rm(directory, { recursive: true, force: true }); }
