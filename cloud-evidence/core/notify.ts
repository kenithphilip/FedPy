/**
 * Drift notifications via Slack and/or PagerDuty.
 * Activated when SLACK_WEBHOOK_URL or PAGERDUTY_INTEGRATION_KEY env vars are set.
 */
export interface DriftEvent {
  ksi_id: string;
  previous_pass: boolean;
  current_pass: boolean;
}

export interface NotifyInput {
  run_id: string;
  drift_events: DriftEvent[];
  total_ksis: number;
  failed_ksis: number;
  evidence_url_base?: string;
}

export async function notifyDrift(input: NotifyInput): Promise<{ slack?: 'sent' | 'skipped' | 'error'; pagerduty?: 'sent' | 'skipped' | 'error'; errors?: string[] }> {
  const negative = input.drift_events.filter((d) => d.previous_pass && !d.current_pass);
  if (negative.length === 0) return { slack: 'skipped', pagerduty: 'skipped' };

  const errors: string[] = [];
  let slackResult: 'sent' | 'skipped' | 'error' = 'skipped';
  let pdResult: 'sent' | 'skipped' | 'error' = 'skipped';

  if (process.env.SLACK_WEBHOOK_URL) {
    try {
      const payload = {
        text: `:rotating_light: cloud-evidence drift: ${negative.length} KSI regression(s) in run ${input.run_id}`,
        blocks: [
          { type: 'header', text: { type: 'plain_text', text: `KSI regressions detected (${negative.length})` } },
          { type: 'section', text: { type: 'mrkdwn', text: `Run \`${input.run_id}\` — ${input.failed_ksis} of ${input.total_ksis} KSIs failed. The following regressed from PASS to FAIL:` } },
          ...negative.slice(0, 10).map((d) => ({
            type: 'section' as const,
            text: { type: 'mrkdwn' as const, text: `• *${d.ksi_id}* — was passing, now failing${input.evidence_url_base ? ` · <${input.evidence_url_base}/${d.ksi_id}.json|evidence>` : ''}` },
          })),
          ...(negative.length > 10 ? [{ type: 'context' as const, elements: [{ type: 'mrkdwn' as const, text: `…and ${negative.length - 10} more` }] }] : []),
        ],
      };
      const r = await fetch(process.env.SLACK_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });
      slackResult = r.ok ? 'sent' : 'error';
      if (!r.ok) errors.push(`Slack: ${r.status} ${r.statusText}`);
    } catch (e: any) {
      slackResult = 'error';
      errors.push(`Slack: ${e.message}`);
    }
  }

  if (process.env.PAGERDUTY_INTEGRATION_KEY) {
    try {
      const payload = {
        routing_key: process.env.PAGERDUTY_INTEGRATION_KEY,
        event_action: 'trigger',
        dedup_key: `cloud-evidence-drift-${input.run_id}`,
        payload: {
          summary: `cloud-evidence: ${negative.length} KSI regression(s) — run ${input.run_id}`,
          severity: negative.some((d) => /KSI-IAM-MFA|KSI-IAM-SUS|KSI-CMT-LMC|KSI-MLA-ALA/.test(d.ksi_id)) ? 'critical' : 'error',
          source: 'cloud-evidence',
          custom_details: {
            regressed_ksis: negative.map((d) => d.ksi_id),
            failed_count: input.failed_ksis,
            total_count: input.total_ksis,
            evidence_url_base: input.evidence_url_base,
          },
        },
      };
      const r = await fetch('https://events.pagerduty.com/v2/enqueue', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });
      pdResult = r.ok ? 'sent' : 'error';
      if (!r.ok) errors.push(`PagerDuty: ${r.status} ${r.statusText}`);
    } catch (e: any) {
      pdResult = 'error';
      errors.push(`PagerDuty: ${e.message}`);
    }
  }

  return { slack: slackResult, pagerduty: pdResult, errors: errors.length ? errors : undefined };
}
