import { vi } from 'vitest';
import type { AuditEntry, CertificateRequest } from '../api';

export const pem = '-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----';
export const chainPem = '-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----';

export const request: CertificateRequest = {
  uid: 'request-1',
  namespace: 'production',
  name: 'api-tls',
  issuerKind: 'ClusterIssuer',
  issuerName: 'manual-ca',
  state: 'pending',
  dnsNames: ['api.example.test', 'www.example.test'],
  createdAt: '2026-11-08T09:00:00Z',
  updatedAt: '2026-11-08T10:00:00Z',
  trustVerified: false,
  version: 7,
};

export const auditEntry: AuditEntry = {
  id: 'audit-1',
  actor: 'operator@example.test',
  action: 'request.created',
  outcome: 'success',
  detail: 'CSR received from cert-manager',
  createdAt: request.createdAt,
};

export function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
}

export function mockApi(
  override?: (url: string, init?: RequestInit) => Response | Promise<Response> | undefined,
) {
  const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const result = override?.(url, init);
    if (result !== undefined) return result;
    if (url === '/api/me') return json({ actor: 'operator@example.test' });
    if (url === '/api/requests/request-1') return json(request);
    if (url === '/api/requests/request-1/audit') return json([auditEntry]);
    if (url.startsWith('/api/requests?') || url === '/api/requests') return json([request]);
    throw new Error(`Unexpected fetch: ${url}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(complete => { resolve = complete; });
  return { promise, resolve };
}
