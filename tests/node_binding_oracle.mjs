// Authored scope fixtures only. Never load application or dependency files.
import {compileFunction} from 'node:vm';
import {readFileSync} from 'node:fs';
const cases=JSON.parse(readFileSync(0,'utf8'));
const hits=cases.map(code=>{
  const observed=[];
  const fakeRequire=specifier=>{observed.push(specifier);return undefined;};
  compileFunction(code,['require','module','exports','__filename','__dirname'])(fakeRequire,{}, {},'fixture.cjs','.');
  return observed;
});
console.log(JSON.stringify({node:process.version,hits}));
