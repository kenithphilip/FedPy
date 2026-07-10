/**
 * AWS FedRAMP reference-architecture audit (AWS-CHK).
 *
 * Checks a running AWS environment against the hardening a FedRAMP-compliant build
 * is expected to have, derived clean-room from the Coalfire AWS RAMPpak reference
 * architecture (research report 02 — idea source, MIT; no code copied). Emitted as
 * its own `AUDIT-REFARCH-AWS.json` evidence file so the findings flow into the NIST
 * 800-53 benchmark (via nist_controls), OSCAL, the crosswalk, and the signed manifest.
 *
 * Read-only (guardrail-wrapped clients). Each check degrades to a WARNING — not a
 * false failure — when its API isn't accessible (e.g. not an Organizations
 * management account, or the service isn't enabled).
 */
import { ListKeysCommand, DescribeKeyCommand } from '@aws-sdk/client-kms';
import { GetEnabledStandardsCommand } from '@aws-sdk/client-securityhub';
import { ListFirewallsCommand } from '@aws-sdk/client-network-firewall';
import { DescribeFlowLogsCommand, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { ListPoliciesCommand, ListDelegatedAdministratorsCommand, ListAWSServiceAccessForOrganizationCommand } from '@aws-sdk/client-organizations';
import { DescribeTrailsCommand } from '@aws-sdk/client-cloudtrail';
import { ListBackupPlansCommand, ListBackupSelectionsCommand } from '@aws-sdk/client-backup';
import { ListBucketsCommand, GetBucketEncryptionCommand } from '@aws-sdk/client-s3';
import { ListTablesCommand } from '@aws-sdk/client-dynamodb';
import * as aws from '../../core/auth/aws.ts';
import type { EvidenceFile, Finding, ProviderBlock, RawEvidence } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

export interface RefArchCtx { runId: string; frmrVersion: string; }

export async function collectAwsReferenceArch(auth: aws.AwsAuth, account: string | null, ctx: RefArchCtx): Promise<EvidenceFile> {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  const evidence: RawEvidence[] = [];
  const region = auth.region;

  // 1) Customer-managed KMS keys (CMK) are in use (not just AWS-managed).
  try {
    const kms = aws.kms(auth);
    const list = await kms.send(new ListKeysCommand({ Limit: 100 }));
    let customer = 0; let awsManaged = 0; let sampled = 0;
    for (const k of (list.Keys ?? []).slice(0, 60)) {
      if (!k.KeyId) continue;
      try {
        const d = await kms.send(new DescribeKeyCommand({ KeyId: k.KeyId }));
        sampled++;
        if (d.KeyMetadata?.KeyManager === 'CUSTOMER') customer++; else awsManaged++;
      } catch { /* per-key */ }
    }
    evidence.push(ev('kms.key_manager_sample', { sampled, customer_managed: customer, aws_managed: awsManaged }));
    findings.push(finding({
      rule: 'aws.kms.customer_managed_keys_in_use', passed: customer > 0, severity: 'high',
      current: { summary: `${customer} customer-managed CMK(s) of ${sampled} sampled (${awsManaged} AWS-managed).`, observations: { customer, awsManaged, sampled } },
      target: { summary: 'In-scope data is encrypted under customer-managed KMS keys (CMKs), not AWS-managed keys, so the CSP controls key rotation/policy.', rationale: 'NIST SC-12, SC-28(1). FedRAMP reference builds use per-service CMKs.' },
      gap: { description: 'No customer-managed CMKs found; encryption may rely solely on AWS-managed keys.', affected_resources: [{ type: 'aws_kms_key', identifier: 'none', attributes: {} }] },
      remediation: { summary: 'Create per-service CMKs and point S3/EBS/RDS/etc. default encryption at them.', options: [{ approach: 'Provision CMKs via Terraform with rotation enabled.', mechanism: 'terraform', steps: ['Create aws_kms_key per service with enable_key_rotation = true', 'Set bucket/volume/db default encryption to the CMK ARN'] }] },
      nist_controls: ['sc-12', 'sc-13', 'sc-28', 'sc-28.1'],
      cross_ksi_dependencies: [{ ksi_id: 'KSI-SVC-RUD', relationship: 'shares-remediation', note: 'CMK encryption underpins data-at-rest KSIs.' }],
    }));
  } catch (e: any) { warnings.push(`KMS (kms:ListKeys): ${e.message}`); }

  // 2) Security Hub standards: CIS AWS Foundations + AWS FSBP enrolled.
  try {
    const sh = aws.securityhub(auth);
    const r = await sh.send(new GetEnabledStandardsCommand({}));
    const arns = (r.StandardsSubscriptions ?? []).map((s) => s.StandardsArn ?? s.StandardsSubscriptionArn ?? '');
    const cis = arns.some((a) => /cis-aws-foundations/i.test(a));
    const fsbp = arns.some((a) => /aws-foundational-security-best-practices/i.test(a));
    evidence.push(ev('securityhub.enabled_standards', { cis, fsbp, count: arns.length }));
    findings.push(finding({
      rule: 'aws.securityhub.standards_enrolled', passed: cis && fsbp, severity: 'medium',
      current: { summary: `Security Hub standards — CIS AWS Foundations: ${cis ? 'on' : 'off'}, AWS FSBP: ${fsbp ? 'on' : 'off'}.`, observations: { cis, fsbp } },
      target: { summary: 'Security Hub has both the CIS AWS Foundations Benchmark and AWS Foundational Security Best Practices standards enabled.', rationale: 'NIST CA-7, RA-5. Continuous control monitoring baseline.' },
      gap: { description: 'One or both expected Security Hub standards are not enrolled.', affected_resources: [{ type: 'aws_securityhub_standards_subscription', identifier: 'none', attributes: { cis, fsbp } }] },
      remediation: { summary: 'Enable the CIS AWS Foundations + AWS FSBP standards in Security Hub.', options: [{ approach: 'Subscribe both standards org-wide.', mechanism: 'console', steps: ['Security Hub → Security standards → enable CIS AWS Foundations Benchmark', 'Enable AWS Foundational Security Best Practices'] }] },
      nist_controls: ['ca-7', 'ra-5', 'ca-2'],
    }));
  } catch (e: any) { warnings.push(`Security Hub (securityhub:GetEnabledStandards): ${e.message}`); }

  // 3) AWS Network Firewall present.
  try {
    const nf = aws.networkFirewall(auth);
    const r = await nf.send(new ListFirewallsCommand({}));
    const count = (r.Firewalls ?? []).length;
    evidence.push(ev('networkfirewall.firewalls', { count }));
    findings.push(finding({
      rule: 'aws.networkfirewall.present', passed: count > 0, severity: 'medium',
      current: { summary: count > 0 ? `${count} AWS Network Firewall(s) deployed.` : 'No AWS Network Firewall deployed.', observations: { count } },
      target: { summary: 'AWS Network Firewall (stateful inspection / egress filtering) protects the VPC perimeter in dedicated firewall subnets.', rationale: 'NIST SC-7, SC-7(5). FedRAMP reference builds centralize egress through Network Firewall.' },
      gap: { description: 'No managed network firewall — egress/ingress filtering may rely on security groups alone.', affected_resources: [{ type: 'aws_networkfirewall_firewall', identifier: 'none', attributes: {} }] },
      remediation: { summary: 'Deploy AWS Network Firewall with stateful Suricata + FQDN-denylist rule groups.', options: [{ approach: 'Terraform Network Firewall + dedicated firewall subnets + routing.', mechanism: 'terraform', steps: ['Create firewall policy with stateful rule groups', 'Route egress through firewall subnets'] }] },
      nist_controls: ['sc-7', 'sc-7.5'],
      cross_ksi_dependencies: [{ ksi_id: 'KSI-CNA-MAT', relationship: 'shares-remediation', note: 'Network boundary protection.' }],
    }));
  } catch (e: any) { warnings.push(`Network Firewall (network-firewall:ListFirewalls): ${e.message}`); }

  // 4) VPC flow logs active.
  try {
    const ec2 = aws.ec2(auth);
    const r = await ec2.send(new DescribeFlowLogsCommand({ MaxResults: 100 }));
    const active = (r.FlowLogs ?? []).filter((f) => f.FlowLogStatus === 'ACTIVE').length;
    evidence.push(ev('ec2.flow_logs', { total: (r.FlowLogs ?? []).length, active }));
    findings.push(finding({
      rule: 'aws.vpc.flow_logs_active', passed: active > 0, severity: 'medium',
      current: { summary: `${active} active VPC flow log(s).`, observations: { active } },
      target: { summary: 'VPC flow logs are enabled (ideally to a KMS-encrypted destination with ≥30-day retention).', rationale: 'NIST AU-2, AU-12, SC-7. Network telemetry for incident response.' },
      gap: { description: 'No active VPC flow logs — east/west + egress network activity is not recorded.', affected_resources: [{ type: 'aws_flow_log', identifier: 'none', attributes: {} }] },
      remediation: { summary: 'Enable VPC flow logs to CloudWatch Logs / S3 with retention.', options: [{ approach: 'Terraform aws_flow_log per VPC.', mechanism: 'terraform', steps: ['Create flow log to a KMS-encrypted log group', 'Set retention ≥ 30 days'] }] },
      nist_controls: ['au-2', 'au-12', 'sc-7'],
    }));
  } catch (e: any) { warnings.push(`VPC flow logs (ec2:DescribeFlowLogs): ${e.message}`); }

  // 5) Organizations: SCPs enabled + delegated security administrators (management account only).
  try {
    const org = aws.organizations(auth);
    const pol = await org.send(new ListPoliciesCommand({ Filter: 'SERVICE_CONTROL_POLICY' }));
    const scps = (pol.Policies ?? []).filter((p) => p.Name !== 'FullAWSAccess');
    let delegated = 0;
    try { const da = await org.send(new ListDelegatedAdministratorsCommand({})); delegated = (da.DelegatedAdministrators ?? []).length; } catch { /* */ }
    evidence.push(ev('organizations.scps', { custom_scps: scps.length, delegated_admins: delegated }));
    findings.push(finding({
      rule: 'aws.organizations.scps_and_delegated_admin', passed: scps.length > 0, severity: 'medium',
      current: { summary: `${scps.length} custom SCP(s); ${delegated} delegated administrator(s).`, observations: { custom_scps: scps.length, delegated } },
      target: { summary: 'Organization-wide Service Control Policies constrain member accounts, and security services use delegated administration.', rationale: 'NIST AC-3, AC-6, CM-7. Preventive org guardrails.' },
      gap: { description: 'No custom SCPs beyond the default FullAWSAccess — member accounts are unconstrained.', affected_resources: [{ type: 'aws_organizations_policy', identifier: 'none', attributes: {} }] },
      remediation: { summary: 'Attach baseline SCPs (deny root, region lock, deny disabling security services).', options: [{ approach: 'Terraform SCPs attached at the org/OU root.', mechanism: 'terraform', steps: ['Author deny-list SCPs', 'Attach to OUs', 'Delegate GuardDuty/Config/Security Hub admin'] }] },
      nist_controls: ['ac-3', 'ac-6', 'cm-7'],
    }));
  } catch (e: any) { warnings.push(`Organizations SCPs (organizations:ListPolicies — management account only): ${e.message}`); }

  // 6) Organizations: trusted access for core security services.
  try {
    const org = aws.organizations(auth);
    const r = await org.send(new ListAWSServiceAccessForOrganizationCommand({}));
    const trusted = new Set((r.EnabledServicePrincipals ?? []).map((s) => s.ServicePrincipal ?? ''));
    const expected = ['guardduty.amazonaws.com', 'securityhub.amazonaws.com', 'config.amazonaws.com', 'cloudtrail.amazonaws.com', 'access-analyzer.amazonaws.com'];
    const missing = expected.filter((s) => !trusted.has(s));
    evidence.push(ev('organizations.trusted_services', { trusted: [...trusted], missing }));
    findings.push(finding({
      rule: 'aws.organizations.security_services_trusted', passed: missing.length === 0, severity: 'medium',
      current: { summary: missing.length === 0 ? 'All core security services have org trusted access.' : `Missing org trusted access: ${missing.join(', ')}.`, observations: { missing } },
      target: { summary: 'GuardDuty, Security Hub, Config, CloudTrail, and IAM Access Analyzer have organization trusted access enabled.', rationale: 'NIST CA-7, SI-4. Org-wide security telemetry.' },
      gap: { description: 'One or more core security services lack org trusted access.', affected_resources: missing.map((s) => ({ type: 'aws_organizations_trusted_service', identifier: s, attributes: {} })) },
      remediation: { summary: 'Enable trusted access for the missing services.', options: [{ approach: 'aws organizations enable-aws-service-access.', mechanism: 'cli', steps: missing.map((s) => `enable-aws-service-access --service-principal ${s}`) }] },
      nist_controls: ['ca-7', 'si-4'],
    }));
  } catch (e: any) { warnings.push(`Organizations trusted services (organizations:ListAWSServiceAccessForOrganization — management account only): ${e.message}`); }

  // 7) CloudTrail → CloudWatch Logs delivery.
  try {
    const ct = aws.cloudtrail(auth);
    const r = await ct.send(new DescribeTrailsCommand({}));
    const toCw = (r.trailList ?? []).filter((t) => !!t.CloudWatchLogsLogGroupArn).length;
    evidence.push(ev('cloudtrail.to_cloudwatch', { trails: (r.trailList ?? []).length, to_cloudwatch: toCw }));
    findings.push(finding({
      rule: 'aws.cloudtrail.delivers_to_cloudwatch', passed: toCw > 0, severity: 'medium',
      current: { summary: `${toCw} trail(s) deliver to CloudWatch Logs.`, observations: { to_cloudwatch: toCw } },
      target: { summary: 'At least one CloudTrail delivers to CloudWatch Logs so metric filters/alarms can act on API activity in near-real-time.', rationale: 'NIST AU-6, AU-12, SI-4.' },
      gap: { description: 'No trail delivers to CloudWatch Logs — alerting on API events is not wired.', affected_resources: [{ type: 'aws_cloudtrail', identifier: 'none', attributes: {} }] },
      remediation: { summary: 'Point a trail at a CloudWatch log group and add metric-filter alarms.', options: [{ approach: 'Terraform CloudWatch log group + trail CloudWatchLogsLogGroupArn.', mechanism: 'terraform', steps: ['Create log group + role', 'Set trail cloud_watch_logs_group_arn', 'Add CIS metric-filter alarms'] }] },
      nist_controls: ['au-6', 'au-12', 'si-4'],
    }));
  } catch (e: any) { warnings.push(`CloudTrail (cloudtrail:DescribeTrails): ${e.message}`); }

  // 8) AWS Backup tag-based selection coverage.
  try {
    const backup = aws.backup(auth);
    const plans = await backup.send(new ListBackupPlansCommand({}));
    let tagSelections = 0; let selections = 0;
    for (const p of (plans.BackupPlansList ?? []).slice(0, 25)) {
      if (!p.BackupPlanId) continue;
      try {
        const sel = await backup.send(new ListBackupSelectionsCommand({ BackupPlanId: p.BackupPlanId }));
        for (const s of sel.BackupSelectionsList ?? []) { selections++; if ((s as any).IamRoleArn) { /* count below via detail not needed */ } }
        // Tag-based selections are identified at detail level; presence of any selection is the signal here.
        tagSelections += (sel.BackupSelectionsList ?? []).length;
      } catch { /* per-plan */ }
    }
    evidence.push(ev('backup.selections', { plans: (plans.BackupPlansList ?? []).length, selections, tagSelections }));
    findings.push(finding({
      rule: 'aws.backup.selection_coverage', passed: selections > 0, severity: 'medium',
      current: { summary: `${(plans.BackupPlansList ?? []).length} backup plan(s), ${selections} selection(s).`, observations: { selections } },
      target: { summary: 'AWS Backup plans exist with (ideally tag-driven) resource selections so in-scope resources are protected automatically.', rationale: 'NIST CP-9, CP-10.' },
      gap: { description: 'No AWS Backup selections — resources are not automatically backed up by a plan.', affected_resources: [{ type: 'aws_backup_selection', identifier: 'none', attributes: {} }] },
      remediation: { summary: 'Create a backup plan with a tag-based selection (e.g. backup_policy=daily).', options: [{ approach: 'Terraform aws_backup_plan + aws_backup_selection (selection_tag).', mechanism: 'terraform', steps: ['Define plan rules + lifecycle', 'Add selection_tag for backup_policy', 'Tag in-scope resources'] }] },
      nist_controls: ['cp-9', 'cp-10'],
      cross_ksi_dependencies: [{ ksi_id: 'KSI-RPL-ABO', relationship: 'shares-remediation', note: 'Automated backups.' }],
    }));
  } catch (e: any) { warnings.push(`AWS Backup (backup:ListBackupPlans): ${e.message}`); }

  // 9) Terraform/IaC state integrity (state bucket SSE + lock table present).
  try {
    const s3 = aws.s3(auth);
    const buckets = await s3.send(new ListBucketsCommand({}));
    const stateBuckets = (buckets.Buckets ?? []).filter((b) => /tf-?state|terraform.*state/i.test(b.Name ?? ''));
    let encrypted = 0;
    for (const b of stateBuckets) {
      try { const enc = await s3.send(new GetBucketEncryptionCommand({ Bucket: b.Name })); if (enc.ServerSideEncryptionConfiguration?.Rules?.length) encrypted++; } catch { /* */ }
    }
    let lockTables = 0;
    try { const ddb = aws.dynamodb(auth); const t = await ddb.send(new ListTablesCommand({})); lockTables = (t.TableNames ?? []).filter((n) => /lock|tfstate|terraform/i.test(n)).length; } catch { /* */ }
    evidence.push(ev('iac.state_integrity', { state_buckets: stateBuckets.length, encrypted, lock_tables: lockTables }));
    const found = stateBuckets.length > 0;
    findings.push(finding({
      rule: 'aws.iac.state_integrity', passed: !found || (encrypted === stateBuckets.length && lockTables > 0), severity: 'low',
      current: { summary: found ? `${stateBuckets.length} TF-state bucket(s), ${encrypted} encrypted; ${lockTables} lock table(s).` : 'No Terraform-state bucket detected by name heuristic.', observations: { stateBuckets: stateBuckets.length, encrypted, lockTables } },
      target: { summary: 'Terraform state buckets are encrypted (SSE) and versioned, with a DynamoDB lock table — protecting IaC integrity.', rationale: 'NIST SC-28, CM-2(2).' },
      gap: { description: 'A Terraform-state bucket is unencrypted or has no lock table.', affected_resources: stateBuckets.map((b) => ({ type: 'aws_s3_bucket', identifier: `arn:${aws.awsPartition(region)}:s3:::${b.Name}`, attributes: {} })) },
      remediation: { summary: 'Enable SSE + versioning on the state bucket and add a DynamoDB lock table.', options: [{ approach: 'Configure the backend with encryption + dynamodb_table.', mechanism: 'terraform', steps: ['Enable bucket SSE (CMK) + versioning', 'Create a lock table', 'Set backend "s3" { encrypt = true, dynamodb_table = ... }'] }] },
      nist_controls: ['sc-28', 'cm-2.2'],
      note: found ? undefined : 'Heuristic by bucket name; informational when no state bucket is detected.',
    }));
  } catch (e: any) { warnings.push(`IaC state integrity (s3:ListAllMyBuckets): ${e.message}`); }

  // 10) Approved/STIG AMI provenance for running instances (vs an allow-pattern).
  try {
    const pattern = process.env.CLOUD_EVIDENCE_APPROVED_AMI_PATTERN || null;
    const ec2 = aws.ec2(auth);
    let token: string | undefined; let iter = 0; let running = 0; const offPattern: string[] = []; const amis = new Set<string>();
    do {
      const r = await ec2.send(new DescribeInstancesCommand({ NextToken: token, MaxResults: 200, Filters: [{ Name: 'instance-state-name', Values: ['running'] }] }));
      for (const res of r.Reservations ?? []) for (const inst of res.Instances ?? []) {
        running++; if (inst.ImageId) amis.add(inst.ImageId);
        if (pattern && inst.ImageId && !new RegExp(pattern).test(inst.ImageId) && inst.InstanceId) offPattern.push(inst.InstanceId);
      }
      const next = r.NextToken; token = next && next !== token ? next : undefined;
    } while (token && ++iter < 50);
    evidence.push(ev('ec2.ami_provenance', { running, distinct_amis: amis.size, pattern, off_pattern: offPattern.length }));
    findings.push(finding({
      rule: 'aws.ec2.approved_ami_provenance', passed: !pattern || offPattern.length === 0, severity: 'medium',
      current: { summary: pattern ? `${offPattern.length} of ${running} running instance(s) use an AMI outside the approved pattern.` : `${running} running instance(s) across ${amis.size} AMI(s); no approved-AMI pattern configured.`, observations: { running, distinct_amis: amis.size, off_pattern: offPattern } },
      target: { summary: 'Running instances launch only from approved/STIG-hardened AMIs (set CLOUD_EVIDENCE_APPROVED_AMI_PATTERN to enforce).', rationale: 'NIST CM-2, CM-6, CM-8. Known-good baseline images.' },
      gap: { description: 'Instances run from AMIs outside the approved set.', affected_resources: offPattern.slice(0, 50).map((id) => ({ type: 'aws_instance', identifier: id, attributes: {} })) },
      remediation: { summary: 'Rebuild instances from approved hardened AMIs; restrict launch via SCP/launch templates.', options: [{ approach: 'Standardize on a golden AMI pipeline (EC2 Image Builder).', mechanism: 'terraform', steps: ['Build STIG-hardened AMIs via Image Builder', 'Reference them in launch templates', 'Restrict ec2:RunInstances to approved AMIs via condition'] }] },
      nist_controls: ['cm-2', 'cm-6', 'cm-8'],
      note: pattern ? undefined : 'Informational until CLOUD_EVIDENCE_APPROVED_AMI_PATTERN is set.',
    }));
  } catch (e: any) { warnings.push(`AMI provenance (ec2:DescribeInstances): ${e.message}`); }

  const provider: ProviderBlock = { provider: 'aws', account_id: account, region_set: [region], evidence, findings, warnings };
  return {
    ksi_id: 'AUDIT-REFARCH-AWS',
    ksi_name: 'AWS FedRAMP Reference-Architecture Audit',
    ksi_statement: 'Audit the running AWS environment against FedRAMP reference-architecture hardening expectations (Coalfire AWS RAMPpak-derived): CMK encryption, Security Hub standards, Network Firewall, VPC flow logs, Organizations SCPs/trusted services, CloudTrail→CloudWatch, AWS Backup, and IaC state integrity.',
    scope: 'CLOUD',
    frmr_version: ctx.frmrVersion,
    run_id: ctx.runId,
    collected_at: new Date().toISOString(),
    providers: [provider],
    rollup: {
      pass: findings.every((f) => f.passed),
      passing_findings: findings.filter((f) => f.passed).length,
      failing_findings: findings.filter((f) => !f.passed).length,
      warnings,
      missing_evidence: [],
      alternatives_in_play: 0,
    },
    nist_controls: ['sc-12', 'sc-28', 'ca-7', 'sc-7', 'au-2', 'ac-3', 'cp-9'],
  };
}
