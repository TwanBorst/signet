import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api, ApiError, errorMessage, type CertificateRequest } from './api';
import { ErrorNotice } from './components';

interface Props {
  request: CertificateRequest;
  disabled: boolean;
  onChanged: (request: CertificateRequest) => void;
  onError: (error: unknown) => void;
  onBusyChange: (busy: boolean) => void;
}

const certificatePattern = /-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g;

function validCertificates(value: string): boolean {
  const blocks = value.match(certificatePattern);
  return !!blocks?.length && value.replace(certificatePattern, '').trim() === '';
}

export function RequestActions({ request, disabled, onChanged, onError, onBusyChange }: Props) {
  const [certificate, setCertificate] = useState('');
  const [chain, setChain] = useState('');
  const [reason, setReason] = useState('');
  const [decision, setDecision] = useState<'deny' | 'cancel' | null>(null);
  const [busy, setBusy] = useState(false);
  const [reading, setReading] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const mounted = useRef(true);
  const inFlight = useRef(false);
  const fileGenerations = useRef({ certificate: 0, chain: 0 });
  const reasonInput = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => {
    if (decision) reasonInput.current?.focus();
  }, [decision]);

  async function readFile(file: File | undefined, target: 'certificate' | 'chain') {
    const generation = ++fileGenerations.current[target];
    if (!file) return;
    setError('');
    if (target === 'certificate') setCertificate('');
    else setChain('');
    if (file.size > 2 * 1024 * 1024) {
      setError('PEM files must be 2 MiB or smaller. Choose a smaller file or paste the PEM text.');
      return;
    }
    setReading(value => value + 1);
    try {
      const value = await file.text();
      if (mounted.current && generation === fileGenerations.current[target]) {
        if (target === 'certificate') setCertificate(value);
        else setChain(value);
      }
    } catch {
      if (mounted.current) setError('Could not read this file. Choose it again or paste the PEM text.');
    } finally {
      if (mounted.current) setReading(value => value - 1);
    }
  }

  async function mutate(action: 'upload' | 'deny' | 'cancel') {
    if (inFlight.current || disabled || reading > 0) return;
    setError('');
    setSuccess('');
    if (action === 'upload') {
      if (!validCertificates(certificate) || (chain.trim() && !validCertificates(chain))) {
        setError('Use PEM CERTIFICATE blocks for the signed certificate and optional chain. CSR and private key files are not accepted.');
        return;
      }
    } else if (!reason.trim()) {
      setError('A reason is required. Explain why this request is being denied or cancelled.');
      reasonInput.current?.focus();
      return;
    }
    inFlight.current = true;
    setBusy(true);
    onBusyChange(true);
    try {
      const result = await api.mutate(request.uid, action, action === 'upload'
        ? { certificate: certificate.trim(), chain: chain.trim(), version: request.version }
        : { reason: reason.trim(), version: request.version });
      if (mounted.current) {
        setCertificate('');
        setChain('');
        setReason('');
        setDecision(null);
        setSuccess(action === 'upload' ? 'Certificate uploaded. Check the request status for issuance.'
          : action === 'deny' ? 'Request denied.' : 'Request cancelled.');
      }
      onChanged(result);
    } catch (cause) {
      if (mounted.current) {
        setError(cause instanceof ApiError && cause.status === 409
          ? `${errorMessage(cause)} The request changed. The latest version is being loaded; review it before submitting again.`
          : errorMessage(cause));
        onError(cause);
      }
    } finally {
      inFlight.current = false;
      if (mounted.current) {
        setBusy(false);
        onBusyChange(false);
      }
    }
  }

  function submitUpload(event: FormEvent) {
    event.preventDefault();
    void mutate('upload');
  }

  const canUpload = request.state === 'pending';
  const canCancel = request.state === 'pending' || request.state === 'uploaded';
  const locked = disabled || busy || reading > 0;

  return <div className="request-actions">
    {error && <ErrorNotice message={error} />}
    {success && <p className="notice success" role="status">{success}</p>}
    {canUpload && <form onSubmit={submitUpload}>
      <fieldset disabled={locked}>
        <legend>Upload signed PEM</legend>
        <p className="muted">Use the certificate returned by your signer. The chain is optional. Signet validates the upload on the server.</p>
        <div className="pem-inputs">
          <div>
            <label htmlFor="certificate-file">Signed certificate file</label>
            <input id="certificate-file" type="file" accept=".pem,.crt,.cer,application/x-pem-file"
              onChange={event => void readFile(event.target.files?.[0], 'certificate')} />
            <label htmlFor="certificate-pem">Signed certificate PEM <span className="muted">(required)</span></label>
            <textarea id="certificate-pem" className="mono" rows={6} value={certificate} required spellCheck={false}
              onChange={event => {
                fileGenerations.current.certificate++;
                setCertificate(event.target.value);
              }} placeholder="-----BEGIN CERTIFICATE-----" />
          </div>
          <div>
            <label htmlFor="chain-file">Chain file <span className="muted">(optional)</span></label>
            <input id="chain-file" type="file" accept=".pem,.crt,.cer,application/x-pem-file"
              onChange={event => void readFile(event.target.files?.[0], 'chain')} />
            <label htmlFor="chain-pem">Certificate chain PEM <span className="muted">(optional)</span></label>
            <textarea id="chain-pem" className="mono" rows={6} value={chain} spellCheck={false}
              onChange={event => {
                fileGenerations.current.chain++;
                setChain(event.target.value);
              }} placeholder="-----BEGIN CERTIFICATE-----" />
          </div>
        </div>
        <button type="submit" className="primary">{busy ? 'Submitting…' : 'Upload certificate'}</button>
      </fieldset>
    </form>}
    {reading > 0 && <p role="status">Reading PEM file…</p>}
    {canCancel && <div className="decision-section">
      <div id="decision-warning" className="notice warning" role="note">
        <strong>Denial or cancellation does not prevent a replacement request</strong>
        <p>Denying or cancelling fails the current CertificateRequest (CR). cert-manager may automatically request a replacement with a new UID. These actions do not change approval to Denied on an already Approved request.</p>
      </div>
      {!decision ? <div className="button-group">
        {canUpload && <button type="button" disabled={locked} aria-describedby="decision-warning" onClick={() => {
          setError('');
          setDecision('deny');
        }}>Deny request</button>}
        <button type="button" disabled={locked} aria-describedby="decision-warning" onClick={() => {
          setError('');
          setDecision('cancel');
        }}>Cancel request</button>
      </div> : <form aria-describedby="decision-warning" onSubmit={event => {
        event.preventDefault();
        void mutate(decision);
      }}>
        <fieldset disabled={locked}>
          <legend>{decision === 'deny' ? 'Deny this request' : 'Cancel this request'}</legend>
          <p>This decision is recorded in the audit trail. Review the request before confirming.</p>
          <label htmlFor="decision-reason">Reason <span className="muted">(required)</span></label>
          <textarea id="decision-reason" ref={reasonInput} rows={3} required value={reason}
            onChange={event => setReason(event.target.value)} />
          <div className="button-group">
            <button type="submit" className="danger" aria-describedby="decision-warning">{busy ? 'Submitting…' : decision === 'deny' ? 'Confirm denial' : 'Confirm cancellation'}</button>
            <button type="button" onClick={() => {
              setDecision(null);
              setReason('');
              setError('');
            }}>Keep request</button>
          </div>
        </fieldset>
      </form>}
    </div>}
    {!canCancel && <p className="empty-inline">This request is {request.state}. No manual signing actions are available.</p>}
  </div>;
}
