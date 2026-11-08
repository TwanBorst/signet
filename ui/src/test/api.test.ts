import { describe, expect, it, vi } from 'vitest';
import { api, ApiError } from '../api';
import { json, request } from './fixtures';

describe('same-origin API adapter', () => {
  it('encodes request identifiers and includes mutation safeguards', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(request));
    vi.stubGlobal('fetch', fetchMock);
    await api.mutate('uid/with ?#', 'cancel', { reason: 'Cancelled by operator', version: 42 });
    expect(fetchMock).toHaveBeenCalledWith('/api/requests/uid%2Fwith%20%3F%23/cancel',
      expect.objectContaining({ credentials: 'same-origin', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Signet-CSRF': '1' },
        body: '{"reason":"Cancelled by operator","version":42}' }));
  });

  it('exposes server errors and status codes for version conflict handling', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'Version changed' }, 409)));
    await expect(api.request('request-1')).rejects.toMatchObject({
      name: 'ApiError', message: 'Version changed', status: 409,
    });
  });

  it('handles non-JSON error responses safely', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<h1>Sign in</h1>', { status: 401 })));
    await expect(api.me()).rejects.toEqual(new ApiError('Request failed (401). Please try again.', 401));
  });

  it('reports network failures rather than substituting mock data', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    await expect(api.requests('', '', '')).rejects.toThrow('Failed to fetch');
  });
});
