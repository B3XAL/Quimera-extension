import { spawnSync } from 'node:child_process';
import {
  cpSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
const allTargets = ['firefox', 'chrome', 'edge', 'opera', 'safari'];
const targets = process.argv.includes('--safari-only')
  ? ['safari']
  : allTargets;

for (const target of targets) {
  const output = path.join(root, 'build', target);
  rmSync(output, { recursive: true, force: true });
  mkdirSync(output, { recursive: true });
  cpSync(path.join(root, 'quimera.js'), path.join(output, 'quimera.js'));
  if (target === 'firefox') {
    cpSync(
      path.join(root, 'firefox-background.html'),
      path.join(output, 'firefox-background.html')
    );
  }
  cpSync(path.join(root, 'interface'), path.join(output, 'interface'), {
    recursive: true,
  });
  cpSync(path.join(root, 'content'), path.join(output, 'content'), {
    recursive: true,
  });
  cpSync(path.join(root, 'icons'), path.join(output, 'icons'), {
    recursive: true,
  });

  const manifest = JSON.parse(
    readFileSync(path.join(root, `manifest.${target}.json`), 'utf8')
  );
  manifest.version = pkg.version;
  writeFileSync(
    path.join(output, 'manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n'
  );

  const envPath = path.join(output, 'interface', 'lib', 'env.js');
  writeFileSync(
    envPath,
    readFileSync(envPath, 'utf8').replace('@@browser_name', target)
  );

  if (target !== 'safari' && !process.argv.includes('--safari-only')) {
    const destination = path.join(root, 'dist', pkg.version);
    mkdirSync(destination, { recursive: true });
    const archive = path.join(
      destination,
      `${pkg.name}-${target}-${pkg.version}.zip`
    );
    rmSync(archive, { force: true });
    const zip = spawnSync('zip', ['-q', '-r', archive, '.'], {
      cwd: output,
      stdio: 'inherit',
    });
    if (zip.status !== 0) throw new Error(`zip failed for ${target}`);
  }
}
