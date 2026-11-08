import { useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage, type AuditEntry, type CertificateRequest } from './api';
import { downloadBlob, ErrorNotice, Loading, safeFilename, Status, Timestamp } from './components';
import { RequestActions } from './RequestActions';

interface Props {
  uid: string;
  actorAvailable: boolean;
  onBack: () => void;
  onChanged: () => void;
}

export function RequestDetail({ uid, actorAvailable, onBack, onChanged }: Props) {
  const [request, setRequest] = useState<CertificateRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [auditLoading, setAuditLoading] = useState(true);
  const [auditError, setAuditError] = useState('');
  const [auditRevision, setAuditRevision] = useState(0);
  const [auditQuery, setAuditQuery] = useState('');
  const [certificateQuery, setCertificateQuery] = useState('');
  const [downloading, setDownloading] = useState(false);
  const [mutating, setMutating] = useState(false);
  const [downloadError, setDownloadError] = useState('');
  const [notice, setNotice] = useState('');
  const heading = useRef<HTMLHeadingElement>(null);
  const mounted = useRef(true);
  const downloadInFlight = useRef(false);

  useEffect(() => {
    mounted.current = true;
    heading.current?.focus();
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    api.request(uid, controller.signal).then(result => {
      if (!controller.signal.aborted) setRequest(result);
    }).catch(reason => {
      if (!controller.signal.aborted) setError(errorMessage(reason));
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [uid, revision]);

  useEffect(() => {
    const controller = new AbortController();
    setAuditLoading(true);
    setAuditError('');
    api.audit(uid, controller.signal).then(result => {
      if (!controller.signal.aborted) setAudit(result);
    }).catch(reason => {
      if (!controller.signal.aborted) setAuditError(errorMessage(reason));
    }).finally(() => {
      if (!controller.signal.aborted) setAuditLoading(false);
    });
    return () => controller.abort();
  }, [uid, auditRevision]);

  async function downloadCSR() {
    if (!request || downloadInFlight.current) return;
    downloadInFlight.current = true;
    setDownloading(true);
    setDownloadError('');
    setNotice('');
    try {
      const blob = await api.csr(uid);
      if (mounted.current) {
        downloadBlob(blob, `${safeFilename(request.name)}.csr.pem`);
        setNotice('CSR download started. This access has been audited.');
      }
    } catch (reason) {
      if (mounted.current) setDownloadError(errorMessage(reason));
    } finally {
      downloadInFlight.current = false;
      if (mounted.current) {
        setDownloading(false);
        setAuditRevision(value => value + 1);
      }
    }
  }

  function changed(updated: CertificateRequest) {
    if (mounted.current) {
      setRequest(updated);
      setAuditRevision(value => value + 1);
    }
    onChanged();
  }

  function conflict(reason: unknown) {
    if (reason instanceof ApiError && reason.status === 409) {
      setRevision(value => value + 1);
      setAuditRevision(value => value + 1);
      onChanged();
    }
  }

  const filteredAudit = audit.filter(entry => [entry.actor, entry.action, entry.outcome, entry.detail, entry.createdAt]
    .some(value => value.toLocaleLowerCase().includes(auditQuery.toLocaleLowerCase())));
  const certificateMatch = !!request && [request.certificate, request.chain]
    .some(value => value?.toLocaleLowerCase().includes(certificateQuery.toLocaleLowerCase()));

  return <section aria-labelledby="detail-heading">
    <div className="detail-toolbar">
      <button type="button" disabled={mutating} onClick={onBack}>← Back to requests</button>
      <button type="button" disabled={loading || downloading || mutating} onClick={() => {
        setRevision(value => value + 1);
        setAuditRevision(value => value + 1);
      }}>Refresh request</button>
    </div>
    <h1 id="detail-heading" ref={heading} tabIndex={-1}>Request details</h1>
    {loading ? <Loading label="Loading request…" /> : error ? <ErrorNotice message={error}
      retry={() => setRevision(value => value + 1)} /> : request && <>
      <div className="request-title"><h2>{request.namespace} / {request.name}</h2><Status state={request.state} /></div>
      <dl className="metadata">
        <div><dt>Request UID</dt><dd className="mono">{request.uid}</dd></div>
        <div><dt>Issuer</dt><dd>{request.issuerKind} / {request.issuerName}</dd></div>
        <div><dt>DNS names</dt><dd>{request.dnsNames.length ? <ul className="dns-list">
          {request.dnsNames.map((name, index) => <li key={`${name}-${index}`}>{name}</li>)}
        </ul> : 'No DNS names'}</dd></div>
        <div><dt>Requested usages</dt><dd>{request.usages === undefined ? 'Not provided'
          : request.usages.length ? <ul className="dns-list">
            {request.usages.map((usage, index) => <li key={`${usage}-${index}`}>{usage}</li>)}
          </ul> : 'No usages specified'}</dd></div>
        <div><dt>Requested validity (Go duration)</dt><dd>{request.duration || 'Not provided'}</dd></div>
        <div><dt>CA certificate requested</dt><dd>{request.isCA === undefined ? 'Not provided'
          : request.isCA ? 'Yes' : 'No'}</dd></div>
        <div><dt>Requester (Kubernetes authenticated creator)</dt><dd>{request.requester || 'Not provided'}</dd></div>
        <div><dt>Version</dt><dd>{request.version}</dd></div>
        <div><dt>Created</dt><dd><Timestamp value={request.createdAt} /></dd></div>
        <div><dt>Last updated</dt><dd><Timestamp value={request.updatedAt} /></dd></div>
        {request.reason && <div className="full-width"><dt>Reason</dt><dd className="preserve">{request.reason}</dd></div>}
      </dl>
      {!request.trustVerified && <div className="notice warning" role="note">
        <strong>Certificate trust is unverified</strong>
        <p>Signet has not verified this certificate’s trust. Independently validate the certificate and chain before relying on them.</p>
      </div>}
      {request.trustVerified && <p className="verified">Certificate trust verified</p>}
      <section className="detail-section" aria-labelledby="csr-heading">
        <div className="section-heading">
          <div><h2 id="csr-heading">Manual signing</h2><p className="muted">Download the PEM CSR for your signing process. Every access is audited; the CSR is never previewed here.</p></div>
          <button type="button" className="primary" disabled={downloading || mutating || !actorAvailable} onClick={downloadCSR}>
            {downloading ? 'Downloading CSR…' : 'Download PEM CSR'}
          </button>
        </div>
        {downloadError && <ErrorNotice message={downloadError} />}
        {notice && <p role="status" className="notice success">{notice}</p>}
        {!actorAvailable && <p className="notice warning">Request actions are unavailable until your signed-in identity is loaded.</p>}
        <RequestActions request={request} disabled={!actorAvailable || downloading} onChanged={changed} onError={conflict}
          onBusyChange={setMutating} />
      </section>
      <section className="detail-section" aria-labelledby="certificate-heading">
        <h2 id="certificate-heading">Certificate & chain</h2>
        {request.certificate || request.chain ? <>
          <label htmlFor="certificate-search">Find text in stored PEM</label>
          <input id="certificate-search" type="search" value={certificateQuery}
            onChange={event => setCertificateQuery(event.target.value)} placeholder="Certificate or chain text" />
          {certificateQuery && <p role="status" className="muted">
            {certificateMatch ? 'Matching text found in the stored PEM.' : 'No matching text in the stored PEM.'}
          </p>}
          {request.certificate && <PemContent title="Signed certificate" value={request.certificate}
            filename={`${safeFilename(request.name)}.certificate.pem`} />}
          {request.chain && <PemContent title="Certificate chain" value={request.chain}
            filename={`${safeFilename(request.name)}.chain.pem`} />}
        </> : <p className="empty-inline">No certificate or chain has been uploaded.</p>}
      </section>
    </>}
    <section className="detail-section" aria-labelledby="audit-heading">
      <div className="section-heading"><div><h2 id="audit-heading">Audit trail</h2>
        <p className="muted">Recorded actions and outcomes for this request, with no date cutoff.</p></div>
        <button type="button" disabled={auditLoading} onClick={() => setAuditRevision(value => value + 1)}>Refresh audit</button>
      </div>
      <label htmlFor="audit-search">Search this audit trail</label>
      <input id="audit-search" type="search" value={auditQuery} onChange={event => setAuditQuery(event.target.value)}
        placeholder="Actor, action, outcome or detail" />
      {auditLoading ? <Loading label="Loading audit trail…" /> : auditError ? <ErrorNotice message={auditError}
        retry={() => setAuditRevision(value => value + 1)} /> : filteredAudit.length === 0
        ? <p className="empty-inline" role="status">{auditQuery ? 'No matching audit events. Try another search.' : 'No audit events recorded yet.'}</p>
        : <div className="table-scroll" tabIndex={0} role="region" aria-label="Audit table">
          <table><caption className="sr-only">Request audit events</caption><thead><tr>
            <th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Action</th>
            <th scope="col">Outcome</th><th scope="col">Detail</th>
          </tr></thead><tbody>{filteredAudit.map(entry => <tr key={entry.id}>
            <td><Timestamp value={entry.createdAt} /></td><td>{entry.actor}</td><td>{entry.action}</td>
            <td>{entry.outcome}</td><td className="preserve">{entry.detail}</td>
          </tr>)}</tbody></table>
        </div>}
    </section>
  </section>;
}

function PemContent({ title, value, filename }: { title: string; value: string; filename: string }) {
  return <details className="pem-content">
    <summary>{title} · PEM</summary>
    <button type="button" onClick={() => downloadBlob(new Blob([value], { type: 'application/x-pem-file' }), filename)}>
      Download {title.toLocaleLowerCase()}
    </button>
    <pre tabIndex={0} aria-label={title}>{value}</pre>
  </details>;
}
