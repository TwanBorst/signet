import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../App';
import { auditEntry, chainPem, deferred, json, mockApi, pem, request } from './fixtures';

async function openRequest() {
  const user = userEvent.setup();
  render(<App />);
  await user.click(await screen.findByRole('button', { name: 'Open production/api-tls' }));
  await screen.findByRole('button', { name: 'Upload certificate' });
  await screen.findByText('operator@example.test', { selector: 'strong' });
  return user;
}

describe('operator request views', () => {
  it('loads the actor and pending queue without accessing a CSR', async () => {
    const fetchMock = mockApi();
    render(<App />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading requests');
    await screen.findByRole('button', { name: 'Open production/api-tls' });
    expect(screen.getByText('operator@example.test', { selector: 'strong' })).toBeInTheDocument();
    expect(screen.getByText('api.example.test, www.example.test')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/requests?state=pending',
      expect.objectContaining({ credentials: 'same-origin', signal: expect.any(AbortSignal) }));
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/csr'))).toBe(false);
  });

  it('searches indefinite history, filters every status, and clears the search', async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole('button', { name: 'Open production/api-tls' });
    await user.click(screen.getByRole('button', { name: 'History & certificates' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/requests', expect.anything()));
    const input = screen.getByRole('searchbox', { name: 'Search requests, certificates & audit' });
    await user.type(input, 'operator@example.test certificate');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Status' }), 'issued');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/requests?q=operator%40example.test+certificate&state=issued', expect.anything()));
    expect(screen.getByRole('combobox')).toHaveTextContent('All statusespendinguploadedissueddeniedcancelleddeletedfailed');
    await user.click(screen.getByRole('button', { name: 'Clear search' }));
    await waitFor(() => expect(fetchMock).toHaveBeenLastCalledWith('/api/requests?state=issued', expect.anything()));
    expect(input).toHaveValue('');
  });

  it('paginates with the last UID, goes back, and resets the cursor when searching', async () => {
    const page = Array.from({ length: 100 }, (_, index) => ({ ...request, uid: `uid-${index}`, name: `tls-${index}` }));
    const fetchMock = mockApi(url => url.includes('before=') ? json([]) : url.startsWith('/api/requests?') ? json(page) : undefined);
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole('button', { name: 'Open production/tls-0' });
    expect(screen.getByRole('button', { name: 'Newer requests' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Older requests' }));
    await screen.findByText('No matching requests');
    expect(fetchMock).toHaveBeenCalledWith('/api/requests?state=pending&before=uid-99', expect.anything());
    expect(screen.getByRole('button', { name: 'Older requests' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Newer requests' }));
    await screen.findByRole('button', { name: 'Open production/tls-0' });
    await user.click(screen.getByRole('button', { name: 'Older requests' }));
    await screen.findByText('No matching requests');
    await user.type(screen.getByRole('searchbox'), 'api');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await screen.findByRole('button', { name: 'Open production/tls-0' });
    expect(fetchMock).toHaveBeenLastCalledWith('/api/requests?q=api&state=pending', expect.anything());
    expect(screen.getByRole('button', { name: 'Newer requests' })).toBeDisabled();
  });

  it('shows a recoverable error and a meaningful empty queue', async () => {
    let fail = true;
    mockApi(url => url.startsWith('/api/requests?') ? fail ? json({ error: 'Service unavailable' }, 503) : json([]) : undefined);
    const user = userEvent.setup();
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Service unavailable');
    fail = false;
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    await screen.findByText('The queue is clear');
    expect(screen.getByRole('button', { name: 'Older requests' })).toBeDisabled();
  });

  it('does not display stale search results when responses arrive out of order', async () => {
    const first = deferred<Response>();
    const fetchMock = mockApi(url => {
      if (url.includes('q=first')) return first.promise;
      if (url.includes('q=second')) return json([{ ...request, name: 'second-result' }]);
      return undefined;
    });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole('button', { name: 'Open production/api-tls' });
    const input = screen.getByRole('searchbox');
    await user.type(input, 'first');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await user.clear(input);
    await user.type(input, 'second');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await screen.findByRole('button', { name: 'Open production/second-result' });
    first.resolve(json([{ ...request, name: 'stale-result' }]));
    await waitFor(() => {
      const firstCall = fetchMock.mock.calls.find(([url]) => String(url).includes('q=first'));
      expect(firstCall?.[1]?.signal?.aborted).toBe(true);
    });
    expect(screen.queryByRole('button', { name: 'Open production/stale-result' })).not.toBeInTheDocument();
  });

  it('gates actions when identity fails and enables them after retry', async () => {
    let fail = true;
    mockApi(url => url === '/api/me' ? fail ? json({ error: 'Session expired' }, 401) : json({ actor: 'operator@example.test' }) : undefined);
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole('button', { name: 'Open production/api-tls' }));
    expect(await screen.findByRole('button', { name: 'Download PEM CSR' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Upload certificate' })).toBeDisabled();
    fail = false;
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Download PEM CSR' })).toBeEnabled());
  });
});

describe('request details and downloads', () => {
  it.each([true, false])('displays signing parameters with explicit CA request=%s', async isCA => {
    mockApi(url => url === '/api/requests/request-1' ? json({
      ...request,
      usages: ['digital signature', 'server auth'],
      duration: '1h0m0s',
      isCA,
      requester: 'system:serviceaccount:cert-manager:cert-manager',
    }) : undefined);
    await openRequest();
    const usages = screen.getByText('Requested usages').nextElementSibling;
    expect(usages).toHaveRole('definition');
    expect(within(usages as HTMLElement).getAllByRole('listitem').map(item => item.textContent))
      .toEqual(['digital signature', 'server auth']);
    expect(screen.getByText('Requested validity (Go duration)').nextElementSibling).toHaveTextContent('1h0m0s');
    expect(screen.getByText('CA certificate requested').nextElementSibling).toHaveTextContent(isCA ? 'Yes' : 'No');
    expect(screen.getByText('Requester (Kubernetes authenticated creator)').nextElementSibling)
      .toHaveTextContent('system:serviceaccount:cert-manager:cert-manager');
  });

  it('displays missing optional signing parameters without inventing defaults', async () => {
    mockApi();
    await openRequest();
    for (const label of ['Requested usages', 'Requested validity (Go duration)', 'CA certificate requested',
      'Requester (Kubernetes authenticated creator)']) {
      expect(screen.getByText(label).nextElementSibling).toHaveTextContent('Not provided');
    }
  });

  it('distinguishes empty usages from missing usages and preserves Go duration text', async () => {
    mockApi(url => url === '/api/requests/request-1' ? json({
      ...request, usages: [], duration: '2160h0m0s', isCA: false, requester: '',
    }) : undefined);
    await openRequest();
    expect(screen.getByText('Requested usages').nextElementSibling).toHaveTextContent('No usages specified');
    expect(screen.getByText('Requested validity (Go duration)').nextElementSibling).toHaveTextContent('2160h0m0s');
    expect(screen.getByText('CA certificate requested').nextElementSibling).toHaveTextContent('No');
    expect(screen.getByText('Requester (Kubernetes authenticated creator)').nextElementSibling).toHaveTextContent('Not provided');
  });

  it('shows request metadata, warns about unverified trust, and searches audit and PEM', async () => {
    mockApi(url => url === '/api/requests/request-1' ? json({ ...request, certificate: pem, chain: chainPem }) : undefined);
    const user = await openRequest();
    expect(screen.getByText('Certificate trust is unverified')).toBeInTheDocument();
    expect(screen.getByText('request-1')).toBeInTheDocument();
    expect(screen.getByText('ClusterIssuer / manual-ca')).toBeInTheDocument();
    await screen.findByText('CSR received from cert-manager');
    await user.type(screen.getByRole('searchbox', { name: 'Search this audit trail' }), 'not-in-audit');
    expect(screen.getByText('No matching audit events. Try another search.')).toBeInTheDocument();
    await user.clear(screen.getByRole('searchbox', { name: 'Search this audit trail' }));
    await user.type(screen.getByRole('searchbox', { name: 'Search this audit trail' }), 'OPERATOR');
    expect(screen.getByText('CSR received from cert-manager')).toBeInTheDocument();
    await user.type(screen.getByRole('searchbox', { name: 'Find text in stored PEM' }), 'ZGVm');
    expect(screen.getByText('Matching text found in the stored PEM.')).toBeInTheDocument();
    await user.clear(screen.getByRole('searchbox', { name: 'Find text in stored PEM' }));
    await user.type(screen.getByRole('searchbox', { name: 'Find text in stored PEM' }), 'absent');
    expect(screen.getByText('No matching text in the stored PEM.')).toBeInTheDocument();
  });

  it('fetches each CSR access as a blob download, never previews it, and refreshes audit', async () => {
    const csr = '-----BEGIN CERTIFICATE REQUEST-----\nPRIVATE-CSR-CONTENT\n-----END CERTIFICATE REQUEST-----';
    const fetchMock = mockApi(url => url.endsWith('/csr')
      ? new Response(csr, { headers: { 'Content-Type': 'application/x-pem-file' } }) : undefined);
    const createObjectURL = vi.fn(() => 'blob:csr-download');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', class extends URL {
      static createObjectURL = createObjectURL;
      static revokeObjectURL = revokeObjectURL;
    });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const user = await openRequest();
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/csr'))).toBe(false);
    await user.click(screen.getByRole('button', { name: 'Download PEM CSR' }));
    await screen.findByText('CSR download started. This access has been audited.');
    expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(click.mock.instances[0]).toHaveProperty('download', 'api-tls.csr.pem');
    expect(screen.queryByText(/PRIVATE-CSR-CONTENT/)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Download PEM CSR' }));
    await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/csr'))).toHaveLength(2));
    await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/audit')).length).toBeGreaterThanOrEqual(3));
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith('blob:csr-download'), { timeout: 2000 });
  });

  it('reports failed CSR downloads and refreshes their audit trail', async () => {
    const fetchMock = mockApi(url => url.endsWith('/csr') ? json({ error: 'CSR is no longer available' }, 410) : undefined);
    const user = await openRequest();
    await user.click(screen.getByRole('button', { name: 'Download PEM CSR' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('CSR is no longer available');
    await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/audit'))).toHaveLength(2));
    expect(screen.getByRole('button', { name: 'Download PEM CSR' })).toBeEnabled();
  });

  it('loads audit independently when request details fail, and retries details', async () => {
    let fail = true;
    mockApi(url => url === '/api/requests/request-1' ? fail ? json({ error: 'Request not found' }, 404) : json(request) : undefined);
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole('button', { name: 'Open production/api-tls' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Request not found');
    expect(await screen.findByText(auditEntry.detail)).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    await screen.findByRole('button', { name: 'Download PEM CSR' });
    await user.click(screen.getByRole('button', { name: '← Back to requests' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Pending requests' })).toHaveFocus());
  });

  it('retries audit independently and shows an empty trail', async () => {
    let fail = true;
    mockApi(url => url.endsWith('/audit') ? fail ? json({ error: 'Audit unavailable' }, 500) : json([]) : undefined);
    const user = await openRequest();
    expect(await screen.findByRole('alert')).toHaveTextContent('Audit unavailable');
    fail = false;
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    await screen.findByText('No audit events recorded yet.');
  });

  it.each(['issued', 'denied', 'cancelled', 'deleted', 'failed'] as const)(
    'displays retained %s requests without offering mutations', async state => {
      mockApi(url => url === '/api/requests/request-1' ? json({ ...request, state, reason: 'Retained decision', trustVerified: true }) : undefined);
      const user = userEvent.setup();
      render(<App />);
      await user.click(await screen.findByRole('button', { name: 'Open production/api-tls' }));
      await screen.findByText(`This request is ${state}. No manual signing actions are available.`);
      expect(screen.getByText('Retained decision')).toBeInTheDocument();
      expect(screen.getByText('Certificate trust verified')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Upload certificate' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Cancel request' })).not.toBeInTheDocument();
    },
  );
});

describe('versioned operator mutations', () => {
  it.each(['deny', 'cancel'] as const)('describes replacement-UID behavior before and during %s confirmation', async action => {
    mockApi();
    const user = await openRequest();
    const warning = screen.getByText('Denial or cancellation does not prevent a replacement request').parentElement;
    expect(warning).toHaveRole('note');
    expect(warning).toHaveTextContent('fails the current CertificateRequest (CR)');
    expect(warning).toHaveTextContent('cert-manager may automatically request a replacement with a new UID');
    expect(warning).toHaveTextContent('do not change approval to Denied on an already Approved request');
    const button = screen.getByRole('button', { name: action === 'deny' ? 'Deny request' : 'Cancel request' });
    expect(button).toHaveAccessibleDescription(/cert-manager may automatically request a replacement with a new UID/);
    await user.click(button);
    expect(warning).toBeVisible();
    expect(screen.getByRole('button', { name: action === 'deny' ? 'Confirm denial' : 'Confirm cancellation' }))
      .toHaveAccessibleDescription(/already Approved request/);
  });

  it.each([false, true])('uploads signed PEM with optional chain=%s and CSRF header', async withChain => {
    const fetchMock = mockApi((url, init) => url.endsWith('/upload') && init?.method === 'POST'
      ? json({ ...request, state: 'uploaded', certificate: pem, chain: withChain ? chainPem : '', version: 8 }) : undefined);
    const user = await openRequest();
    await user.type(screen.getByRole('textbox', { name: 'Signed certificate PEM (required)' }), pem);
    if (withChain) await user.type(screen.getByRole('textbox', { name: 'Certificate chain PEM (optional)' }), chainPem);
    await user.click(screen.getByRole('button', { name: 'Upload certificate' }));
    await screen.findByText('Certificate uploaded. Check the request status for issuance.');
    expect(fetchMock).toHaveBeenCalledWith('/api/requests/request-1/upload', {
      credentials: 'same-origin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Signet-CSRF': '1' },
      body: JSON.stringify({ certificate: pem, chain: withChain ? chainPem : '', version: 7 }),
    });
    expect(screen.queryByRole('button', { name: 'Upload certificate' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel request' })).toBeInTheDocument();
    await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/audit'))).toHaveLength(2));
  });

  it('rejects private keys, malformed PEM, and invalid chains before sending', async () => {
    const fetchMock = mockApi();
    const user = await openRequest();
    const input = screen.getByRole('textbox', { name: 'Signed certificate PEM (required)' });
    await user.type(input, '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----');
    await user.click(screen.getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('CSR and private key files are not accepted');
    await user.clear(input);
    await user.type(input, pem);
    await user.type(screen.getByRole('textbox', { name: 'Certificate chain PEM (optional)' }), 'not PEM');
    await user.click(screen.getByRole('button', { name: 'Upload certificate' }));
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  });

  it.each(['deny', 'cancel'] as const)('requires a meaningful reason and confirmation for %s', async action => {
    const fetchMock = mockApi((url, init) => url.endsWith(`/${action}`) && init?.method === 'POST'
      ? json({ ...request, state: action === 'deny' ? 'denied' : 'cancelled', reason: 'Wrong DNS name', version: 8 }) : undefined);
    const user = await openRequest();
    await user.click(screen.getByRole('button', { name: action === 'deny' ? 'Deny request' : 'Cancel request' }));
    const reason = screen.getByRole('textbox', { name: 'Reason (required)' });
    expect(reason).toHaveFocus();
    expect(reason).toBeRequired();
    await user.type(reason, '   ');
    await user.click(screen.getByRole('button', { name: action === 'deny' ? 'Confirm denial' : 'Confirm cancellation' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('A reason is required');
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    await user.clear(reason);
    await user.type(reason, '  Wrong DNS name  ');
    await user.click(screen.getByRole('button', { name: action === 'deny' ? 'Confirm denial' : 'Confirm cancellation' }));
    await screen.findByText(action === 'deny' ? 'Request denied.' : 'Request cancelled.');
    expect(fetchMock).toHaveBeenCalledWith(`/api/requests/request-1/${action}`, expect.objectContaining({
      headers: { 'Content-Type': 'application/json', 'X-Signet-CSRF': '1' },
      body: JSON.stringify({ reason: 'Wrong DNS name', version: 7 }),
    }));
  });

  it('allows abandoning a decision without a mutation', async () => {
    const fetchMock = mockApi();
    const user = await openRequest();
    await user.click(screen.getByRole('button', { name: 'Deny request' }));
    await user.type(screen.getByRole('textbox', { name: 'Reason (required)' }), 'A draft reason');
    await user.click(screen.getByRole('button', { name: 'Keep request' }));
    expect(screen.queryByRole('textbox', { name: 'Reason (required)' })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  });

  it('refreshes after a version conflict without automatically retrying the mutation', async () => {
    let conflict = false;
    const fetchMock = mockApi((url, init) => {
      if (url.endsWith('/upload') && init?.method === 'POST') {
        conflict = true;
        return json({ error: 'Version conflict' }, 409);
      }
      if (url === '/api/requests/request-1' && conflict) return json({ ...request, state: 'issued', version: 8 });
      return undefined;
    });
    const user = await openRequest();
    await user.type(screen.getByRole('textbox', { name: 'Signed certificate PEM (required)' }), pem);
    await user.click(screen.getByRole('button', { name: 'Upload certificate' }));
    await screen.findByText('This request is issued. No manual signing actions are available.');
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(fetchMock.mock.calls.filter(([url]) => url === '/api/requests/request-1')).toHaveLength(2);
  });

  it('locks actions while submitting, prevents duplicate mutations, and preserves upload on failure', async () => {
    const upload = deferred<Response>();
    const fetchMock = mockApi(url => url.endsWith('/upload') ? upload.promise : undefined);
    const user = await openRequest();
    await user.type(screen.getByRole('textbox', { name: 'Signed certificate PEM (required)' }), pem);
    await user.dblClick(screen.getByRole('button', { name: 'Upload certificate' }));
    expect(screen.getByRole('button', { name: 'Submitting…' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Refresh request' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Download PEM CSR' })).toBeDisabled();
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    upload.resolve(json({ error: 'Certificate does not match the CSR' }, 422));
    expect(await screen.findByRole('alert')).toHaveTextContent('Certificate does not match the CSR');
    expect(screen.getByRole('textbox', { name: 'Signed certificate PEM (required)' })).toHaveValue(pem);
    expect(screen.getByRole('button', { name: 'Upload certificate' })).toBeEnabled();
  });

  it('loads certificate and chain files into labeled PEM inputs', async () => {
    mockApi();
    const user = await openRequest();
    const certificate = new File([pem], 'signed.pem', { type: 'application/x-pem-file' });
    Object.defineProperty(certificate, 'text', { value: () => Promise.resolve(pem) });
    const chain = new File([chainPem], 'chain.pem', { type: 'application/x-pem-file' });
    Object.defineProperty(chain, 'text', { value: () => Promise.resolve(chainPem) });
    await user.upload(screen.getByLabelText('Signed certificate file'), certificate);
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Signed certificate PEM (required)' })).toHaveValue(pem));
    await user.upload(screen.getByLabelText('Chain file (optional)'), chain);
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Certificate chain PEM (optional)' })).toHaveValue(chainPem));
  });

  it('handles unreadable files and oversized files without reusing an old certificate', async () => {
    mockApi();
    const user = await openRequest();
    const input = screen.getByRole('textbox', { name: 'Signed certificate PEM (required)' });
    await user.type(input, pem);
    const huge = new File(['x'], 'huge.pem', { type: 'application/x-pem-file' });
    Object.defineProperty(huge, 'size', { value: 2 * 1024 * 1024 + 1 });
    await user.upload(screen.getByLabelText('Signed certificate file'), huge);
    expect(await screen.findByRole('alert')).toHaveTextContent('2 MiB or smaller');
    expect(input).toHaveValue('');
    const unreadable = new File(['x'], 'broken.pem', { type: 'application/x-pem-file' });
    Object.defineProperty(unreadable, 'text', { value: () => Promise.reject(new Error('read failed')) });
    await user.upload(screen.getByLabelText('Signed certificate file'), unreadable);
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not read this file');
  });
});
