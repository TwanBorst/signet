import type { RequestState } from './api';

export function Status({ state }: { state: RequestState }) {
  return <span className={`status status-${state}`}>{state}</span>;
}

export function Timestamp({ value }: { value: string }) {
  const date = new Date(value);
  return <time dateTime={value} title={value}>
    {Number.isNaN(date.getTime()) ? value : date.toLocaleString()}
  </time>;
}

export function ErrorNotice({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="notice error" role="alert">
    <p>{message}</p>
    {retry && <button type="button" onClick={retry}>Try again</button>}
  </div>;
}

export function Loading({ label }: { label: string }) {
  return <div role="status" className="loading">
    <p>{label}</p>
    <div className="skeleton" aria-hidden="true" />
    <div className="skeleton short" aria-hidden="true" />
  </div>;
}

export function downloadBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  // Keep the object URL alive until the browser has started the download.
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function safeFilename(name: string) {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_') || 'request';
}
