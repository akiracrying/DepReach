// Resolve only: never import/require a target module or a target loader.
import {createRequire, isBuiltin} from 'node:module';
import {pathToFileURL, fileURLToPath} from 'node:url';
import {statSync, realpathSync} from 'node:fs';
const requests = JSON.parse(process.argv[2]);
const results = requests.map(({file, specifier, mode}) => {
  try {
    const importer = pathToFileURL(realpathSync(file));
    const resolved = mode === 'require'
      ? createRequire(importer).resolve(specifier)
      : import.meta.resolve(specifier, importer);
    if (isBuiltin(resolved)) return {status:'builtin', module:resolved};
    const path = resolved.startsWith('file:') ? fileURLToPath(resolved) : resolved;
    // import.meta.resolve can return URLs for absent files. Check existence
    // explicitly without loading them, matching the loader's file boundary.
    if (!statSync(path).isFile()) return {status:'unresolved', error:'directory'};
    return {status:'resolved', file:path};
  } catch(error) { return {status:'unresolved', error:error.code}; }
});
console.log(JSON.stringify({node:process.version, results}));
