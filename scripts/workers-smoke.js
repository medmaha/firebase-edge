import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

const result = await build({
    entryPoints: ['scripts/workers/worker.js'],
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    write: false,
    logLevel: 'error',
});

const mf = new Miniflare({
    modules: true,
    script: result.outputFiles[0].text,
    compatibilityDate: '2025-01-01',
});

try {
    const res = await mf.dispatchFetch('http://localhost/');
    const body = await res.text();
    if (!res.ok || body !== 'worker-ok') {
        console.error('Workers smoke test failed:\n' + body);
        process.exitCode = 1;
    } else {
        console.log('Cloudflare Workers (workerd) smoke test passed');
    }
} finally {
    await mf.dispose();
}
