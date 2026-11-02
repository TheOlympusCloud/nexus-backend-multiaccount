export function validateBackendProvenance(metadata, filename, config, commit, recipeHash) {
  const suffix = {x64:'x86_64', arm64:'aarch64'}[metadata?.arch];
  if (metadata?.schema !== 2 || metadata.sourceRepository !== config.repository ||
      metadata.version !== config.version || metadata.commit !== commit || metadata.recipeSha256 !== recipeHash ||
      metadata.compatibility !== config.compatibility || metadata.authUi !== 'electron' || metadata.platform !== 'linux' ||
      !suffix || metadata.archive !== `xodus-nexus-backend-${config.version}-linux-${suffix}.tar.xz` ||
      filename !== metadata.archive.replace('.tar.xz', '.manifest.json') ||
      !/^[a-f0-9]{128}$/.test(metadata.archiveSha512 ?? '') ||
      !metadata.files || Object.keys(metadata.files).sort().join(',') !== 'LICENSE,xodus-cli,xodus-service' ||
      Object.values(metadata.files).some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)))
    throw Error('Backend source provenance mismatch');
}
