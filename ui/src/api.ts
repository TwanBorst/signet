export const requestStates = [
  'pending', 'uploaded', 'issued', 'denied', 'cancelled', 'deleted', 'failed',
] as const;

export type RequestState = (typeof requestStates)[number];

export interface CertificateRequest {
  uid: string;
  namespace: string;
  name: string;
  issuerKind: string;
  issuerName: string;
  state: RequestState;
  dnsNames: string[];
  usages?: string[];
  duration?: string;
  isCA?: boolean;
  requester?: string;
  createdAt: string;
  updatedAt: string;
  certificate?: string;
  chain?: string;
  trustVerified: boolean;
  reason?: string;
  version: number;
}

export interface AuditEntry {
  id: string;
  actor: string;
  action: string;
  outcome: string;
  detail: string;
  createdAt: string;
}

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = 'ApiError';
  }
}

async function checkedFetch(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(`/api${path}`, { credentials: 'same-origin', ...init });
  if (!response.ok) {
    let message = `Request failed (${response.status}). Please try again.`;
    try {
      const body: unknown = await response.json();
      if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') {
        message = body.error;
      }
    } catch {
      // A proxy or expired session may return a non-JSON error.
    }
    throw new ApiError(message, response.status);
  }
  return response;
}

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return (await checkedFetch(path, { signal })).json() as Promise<T>;
}

function requestPath(uid: string): string {
  return `/requests/${encodeURIComponent(uid)}`;
}

export const api = {
  me: (signal?: AbortSignal) => get<{ actor: string }>('/me', signal),
  requests: (query: string, state: string, before: string, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    if (query) params.set('q', query);
    if (state) params.set('state', state);
    if (before) params.set('before', before);
    const suffix = params.size ? `?${params}` : '';
    return get<CertificateRequest[]>(`/requests${suffix}`, signal);
  },
  request: (uid: string, signal?: AbortSignal) => get<CertificateRequest>(requestPath(uid), signal),
  audit: (uid: string, signal?: AbortSignal) => get<AuditEntry[]>(`${requestPath(uid)}/audit`, signal),
  csr: async (uid: string) => (await checkedFetch(`${requestPath(uid)}/csr`)).blob(),
  mutate: async (
    uid: string,
    action: 'upload' | 'deny' | 'cancel',
    body: { certificate: string; chain: string; version: number } | { reason: string; version: number },
  ): Promise<CertificateRequest> => {
    const response = await checkedFetch(`${requestPath(uid)}/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Signet-CSRF': '1' },
      body: JSON.stringify(body),
    });
    return response.json() as Promise<CertificateRequest>;
  },
};

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'An unexpected error occurred. Please try again.';
}
