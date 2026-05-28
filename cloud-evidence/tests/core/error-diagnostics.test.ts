/**
 * Tests for core/error-diagnostics.ts — classifier + diagnostic helpers.
 */
import { describe, it, expect } from 'vitest';
import {
  classifyError, diagnoseAwsError, diagnoseGcpError, diagnoseK8sError,
} from '../../core/error-diagnostics.ts';

describe('classifyError', () => {
  it('classifies AWS AccessDeniedException', () => {
    expect(classifyError({ name: 'AccessDeniedException', message: 'User is not authorized' })).toBe('access_denied');
    expect(classifyError({ name: 'UnauthorizedException' })).toBe('access_denied');
  });

  it('classifies HTTP 403 as access_denied', () => {
    expect(classifyError({ $metadata: { httpStatusCode: 403 }, name: 'GenericError' })).toBe('access_denied');
  });

  it('classifies throttling errors', () => {
    expect(classifyError({ name: 'ThrottlingException' })).toBe('throttling');
    expect(classifyError({ $metadata: { httpStatusCode: 429 } })).toBe('throttling');
  });

  it('classifies NoSuchEntity as not_found', () => {
    expect(classifyError({ name: 'NoSuchEntityException' })).toBe('not_found');
    expect(classifyError({ $metadata: { httpStatusCode: 404 } })).toBe('not_found');
  });

  it('classifies network errors', () => {
    expect(classifyError({ code: 'ECONNRESET', message: 'connection reset' })).toBe('network');
    expect(classifyError({ code: 'ETIMEDOUT' })).toBe('network');
    expect(classifyError({ name: 'TimeoutError' })).toBe('network');
  });

  it('classifies malformed JSON', () => {
    expect(classifyError(new SyntaxError('Unexpected token } in JSON'))).toBe('malformed_response');
  });

  it('classifies service-not-enabled', () => {
    expect(classifyError({ name: 'OptInRequired' })).toBe('not_enabled');
    expect(classifyError({ name: 'AWSOrganizationsNotInUseException' })).toBe('not_enabled');
  });

  it('falls back to unknown for unrecognized errors', () => {
    expect(classifyError({ name: 'WeirdoError', message: 'x' })).toBe('unknown');
    expect(classifyError(null)).toBe('unknown');
    expect(classifyError(undefined)).toBe('unknown');
  });

  it('falls back to access_denied based on message substring', () => {
    expect(classifyError({ name: 'X', message: 'User abc is not authorized to perform: iam:ListUsers' })).toBe('access_denied');
  });
});

describe('diagnoseAwsError', () => {
  it('returns an actionable message on AccessDenied with the required action', () => {
    const e = { name: 'AccessDeniedException', message: 'User: arn:aws:iam::1:user/ci is not authorized' };
    const out = diagnoseAwsError(e, 'iam.ListUsers', 'iam:ListUsers');
    expect(out).toContain('iam.ListUsers AccessDenied');
    expect(out).toContain('grant iam:ListUsers');
    expect(out).toContain('User:');  // original message included
  });

  it('mentions retry tuning on throttling', () => {
    const e = { name: 'ThrottlingException', message: 'Rate exceeded' };
    const out = diagnoseAwsError(e, 'iam.ListUsers', 'iam:ListUsers');
    expect(out).toMatch(/throttled/);
    expect(out).toMatch(/CLOUD_EVIDENCE_RETRY_ATTEMPTS|retry/);
  });

  it('marks NotFound as expected', () => {
    const e = { name: 'NoSuchEntityException', message: 'No login profile' };
    const out = diagnoseAwsError(e, 'iam.GetLoginProfile', 'iam:GetLoginProfile');
    expect(out).toMatch(/expected/i);
  });

  it('falls back to source: message for unknown', () => {
    const e = { name: 'Weird', message: 'something broke' };
    const out = diagnoseAwsError(e, 'iam.X', 'iam:X');
    expect(out).toMatch(/^iam\.X:/);
  });

  it('handles non-Error inputs without throwing', () => {
    expect(diagnoseAwsError(null, 'iam.X', 'iam:X')).toMatch(/iam\.X/);
    expect(diagnoseAwsError('a string', 'iam.X', 'iam:X')).toMatch(/iam\.X/);
  });
});

describe('diagnoseGcpError', () => {
  it('translates grpc code 7 to PERMISSION_DENIED with required role', () => {
    const out = diagnoseGcpError({ code: 7, message: 'denied' }, 'iam.listServiceAccounts', 'roles/iam.securityReviewer');
    expect(out).toContain('PERMISSION_DENIED');
    expect(out).toContain('roles/iam.securityReviewer');
  });

  it('translates UNAUTHENTICATED (16) to ADC hint', () => {
    const out = diagnoseGcpError({ code: 16, message: 'expired' }, 'compute.list', 'roles/viewer');
    expect(out).toContain('UNAUTHENTICATED');
    expect(out).toContain('gcloud auth application-default login');
  });

  it('handles HTTP-style 403 too', () => {
    const out = diagnoseGcpError({ code: 403, message: 'Permission denied' }, 'logging.list', 'roles/logging.viewer');
    expect(out).toContain('PermissionDenied');
    expect(out).toContain('roles/logging.viewer');
  });
});

describe('diagnoseK8sError', () => {
  it('translates 403 to RBAC binding hint', () => {
    const out = diagnoseK8sError({ statusCode: 403, message: 'forbidden' }, 'rbac.listClusterRoleBinding', 'list', 'clusterrolebindings');
    expect(out).toContain('Forbidden');
    expect(out).toContain('list');
    expect(out).toContain('clusterrolebindings');
  });

  it('translates 401 to expired-kubeconfig hint', () => {
    const out = diagnoseK8sError({ statusCode: 401, message: 'unauthorized' }, 'rbac.list', 'list', 'clusterrolebindings');
    expect(out).toContain('Unauthorized');
    expect(out).toMatch(/update-kubeconfig|get-credentials/);
  });

  it('translates ECONNREFUSED to cluster-unreachable hint', () => {
    const out = diagnoseK8sError({ code: 'ECONNREFUSED', message: 'connection refused' }, 'rbac.list', 'list', 'x');
    expect(out).toContain('unreachable');
  });
});
