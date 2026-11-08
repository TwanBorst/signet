import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api, errorMessage, requestStates, type CertificateRequest } from './api';
import { ErrorNotice, Loading, Status, Timestamp } from './components';
import { RequestDetail } from './RequestDetail';

export function App() {
  const [actor, setActor] = useState('');
  const [identityError, setIdentityError] = useState('');
  const [identityRevision, setIdentityRevision] = useState(0);
  const [view, setView] = useState<'queue' | 'history'>('queue');
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [state, setState] = useState('');
  const [cursors, setCursors] = useState<string[]>(['']);
  const [rows, setRows] = useState<CertificateRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState('');
  const [revision, setRevision] = useState(0);
  const [selectedUid, setSelectedUid] = useState<string | null>(null);
  const listHeading = useRef<HTMLHeadingElement>(null);
  const effectiveState = view === 'queue' ? 'pending' : state;
  const before = cursors[cursors.length - 1] ?? '';

  useEffect(() => {
    const controller = new AbortController();
    setIdentityError('');
    setActor('');
    api.me(controller.signal).then(result => {
      if (!controller.signal.aborted) setActor(result.actor);
    }).catch(error => {
      if (!controller.signal.aborted) setIdentityError(errorMessage(error));
    });
    return () => controller.abort();
  }, [identityRevision]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setListError('');
    setRows([]);
    api.requests(query, effectiveState, before, controller.signal).then(result => {
      if (!controller.signal.aborted) setRows(result);
    }).catch(error => {
      if (!controller.signal.aborted) setListError(errorMessage(error));
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [query, effectiveState, before, revision, view]);

  function switchView(next: 'queue' | 'history') {
    setView(next);
    setCursors(['']);
    setState('');
    setSearch('');
    setQuery('');
    setSelectedUid(null);
  }

  function submitSearch(event: FormEvent) {
    event.preventDefault();
    setQuery(search.trim());
    setCursors(['']);
    setRevision(value => value + 1);
  }

  function closeDetail() {
    setSelectedUid(null);
    window.setTimeout(() => listHeading.current?.focus(), 0);
  }

  return <>
    <a className="skip-link" href="#main">Skip to main content</a>
    <header className="app-header">
      <div><span className="brand">Signet</span><span className="product-label">Certificate operations</span></div>
      <div className="identity">
        {actor ? <>Signed in as <strong>{actor}</strong></> : identityError ? 'Identity unavailable' : 'Loading identity…'}
      </div>
    </header>
    <main id="main" className="workspace">
      {identityError && <ErrorNotice message={`Could not load your identity: ${identityError}`}
        retry={() => setIdentityRevision(value => value + 1)} />}
      <nav className="view-nav" aria-label="Request views">
        <button type="button" aria-current={view === 'queue' ? 'page' : undefined}
          onClick={() => switchView('queue')}>Pending queue</button>
        <button type="button" aria-current={view === 'history' ? 'page' : undefined}
          onClick={() => switchView('history')}>History & certificates</button>
      </nav>
      {selectedUid ? <RequestDetail key={selectedUid} uid={selectedUid} actorAvailable={!!actor}
        onBack={closeDetail} onChanged={() => setRevision(value => value + 1)} /> : <section aria-labelledby="list-heading">
        <div className="section-heading">
          <div>
            <h1 id="list-heading" ref={listHeading} tabIndex={-1}>{view === 'queue' ? 'Pending requests' : 'Request history'}</h1>
            <p className="muted">{view === 'queue'
              ? 'Review a request, download its CSR, then upload the signed certificate.'
              : 'Search retained requests, certificates, and audit records across all dates.'}</p>
          </div>
          <button type="button" disabled={loading} onClick={() => setRevision(value => value + 1)}>Refresh</button>
        </div>
        <form className="search-form" onSubmit={submitSearch} role="search">
          <div className="search-field">
            <label htmlFor="request-search">{view === 'queue' ? 'Search pending requests' : 'Search requests, certificates & audit'}</label>
            <input id="request-search" type="search" value={search}
              onChange={event => setSearch(event.target.value)} placeholder="Name, DNS name, issuer, certificate or audit text" />
          </div>
          {view === 'history' && <div>
            <label htmlFor="state-filter">Status</label>
            <select id="state-filter" value={state} onChange={event => {
              setState(event.target.value);
              setCursors(['']);
            }}>
              <option value="">All statuses</option>
              {requestStates.map(value => <option key={value} value={value}>{value}</option>)}
            </select>
          </div>}
          <button className="primary" type="submit">Search</button>
          {query && <button type="button" onClick={() => {
            setSearch('');
            setQuery('');
            setCursors(['']);
          }}>Clear search</button>}
        </form>
        {loading ? <Loading label="Loading requests…" /> : listError
          ? <ErrorNotice message={listError} retry={() => setRevision(value => value + 1)} />
          : rows.length === 0 ? <div className="empty" role="status">
            <h2>{query || state || before ? 'No matching requests' : view === 'queue' ? 'The queue is clear' : 'No request history yet'}</h2>
            <p>{query || state ? 'Try another search or status filter.' : before
              ? 'There are no older requests. Return to the previous page.'
              : view === 'queue' ? 'New requests will appear here. Refresh to check for updates.'
              : 'Requests will appear here as they are received. No date cutoff is applied.'}</p>
          </div> : <div className="table-scroll" tabIndex={0} role="region" aria-label="Request table">
            <table>
              <caption className="sr-only">{view === 'queue' ? 'Pending certificate requests' : 'Retained certificate requests'}, newest first</caption>
              <thead><tr><th scope="col">Request</th><th scope="col">DNS names</th><th scope="col">Issuer</th>
                <th scope="col">Status</th><th scope="col">Created</th></tr></thead>
              <tbody>{rows.map(row => <tr key={row.uid}>
                <td><button className="text-button request-link" onClick={() => setSelectedUid(row.uid)}
                  aria-label={`Open ${row.namespace}/${row.name}`}>{row.name}</button>
                  <span className="cell-secondary">{row.namespace}</span></td>
                <td><span className="dns-preview">{row.dnsNames.join(', ') || 'No DNS names'}</span></td>
                <td>{row.issuerName}<span className="cell-secondary">{row.issuerKind}</span></td>
                <td><Status state={row.state} /></td><td><Timestamp value={row.createdAt} /></td>
              </tr>)}</tbody>
            </table>
          </div>}
        <div className="pagination" aria-label="Request pagination">
          <p className="muted" aria-live="polite">{loading ? 'Loading page…' : `Page ${cursors.length} · ${rows.length} requests · newest first`}</p>
          <div className="button-group">
            <button type="button" disabled={loading || cursors.length === 1}
              onClick={() => setCursors(values => values.slice(0, -1))}>Newer requests</button>
            <button type="button" disabled={loading || !!listError || rows.length < 100}
              onClick={() => {
                const last = rows[rows.length - 1];
                if (last) setCursors(values => [...values, last.uid]);
              }}>Older requests</button>
          </div>
        </div>
      </section>}
    </main>
    <footer className="app-footer">Signet · Manual certificate signing, with an audit trail.</footer>
  </>;
}
