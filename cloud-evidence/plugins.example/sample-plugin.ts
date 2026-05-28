/**
 * Sample cloud-evidence plugin.
 *
 * Copy this file to `./plugins/` (and rename) to add a custom KSI collector.
 * Then run the orchestrator with --plugins-dir ./plugins.
 *
 * This sample registers a synthetic "KSI-CUSTOM-EXAMPLE" KSI that always
 * passes — replace with real logic that queries your environment.
 */
import type { Plugin } from '../core/plugin-loader.ts';
import type { ProviderBlock } from '../core/envelope.ts';

const samplePlugin: Plugin = {
  name: 'sample-plugin',
  version: '0.1.0',
  description: 'Example KSI collector showing the plugin API surface.',

  register({ registerKsi }) {
    registerKsi({
      id: 'KSI-CUSTOM-EXAMPLE',
      name: 'Custom Example',
      scope: 'CLOUD',
      statement: 'A sample KSI that always passes — replace with real logic.',
      nist_controls: ['CM-2'],
      aws: async (_ctx): Promise<ProviderBlock> => {
        return {
          provider: 'aws',
          account_id: _ctx.aws?.account_id ?? null,
          region_set: _ctx.aws?.region ? [_ctx.aws.region] : [],
          evidence: [],
          findings: [
            {
              rule: 'custom.example.always_pass',
              passed: true,
              severity: 'info',
              current_state: { summary: 'Sample collector always returns pass.', observations: { sample: true } },
              target_state: { summary: 'N/A — this is an example.', rationale: 'Demonstrates the plugin API.' },
            },
          ],
        };
      },
    });
  },
};

export default samplePlugin;
