// Only explicitly authored pytest fixture modules may be loaded by this helper.
// Compare exported function identity; do not invoke the selected function body.
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const request=JSON.parse(readFileSync(0,'utf8'));
try {
  const file=pathToFileURL(request.file);
  const namespace=request.mode==='import' ? await import(file.href) : createRequire(import.meta.url)(request.file);
  const fn=namespace.selected;
  console.log(JSON.stringify(typeof fn==='function'
    ? {node:process.version,status:'function',sha256:createHash('sha256').update(Function.prototype.toString.call(fn)).digest('hex')}
    : {node:process.version,status:'non_function'}));
} catch(error) {console.log(JSON.stringify({node:process.version,status:'error',code:error.code||error.name}));}
