import { defineConfig } from 'tsup';
import { version } from './package.json';

export default defineConfig({
  entry: ['src/index.ts', 'src/cli.ts'],
  format: ['cjs', 'esm'],
  dts: { entry: 'src/index.ts' },
  clean: true,
  sourcemap: true,
  minify: false,
  target: 'es2022',
  define: {
    __SECRET_KIT_VERSION__: JSON.stringify(version),
  },
});
