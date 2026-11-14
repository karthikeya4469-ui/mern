import { useEffect, useRef, useState } from "react";

const CHUNK_SIZE = 4 * 1024 * 1024;
const MAX_TRANSFER_BYTES = 1024 * 1024 * 1024;
const MAX_FILES = 100;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function Icon({ name, size = 20 }) {
  const props = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": true,
  };
  const paths = {
    arrow: <><path d="M5 12h14" /><path d="m13 6 6 6-6 6" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    close: <><path d="m18 6-12 12" /><path d="m6 6 12 12" /></>,
    file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /><path d="M8 13h8M8 17h8" /></>,
    folder: <path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
    link: <><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" /><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" /></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 1 1 8 0v3" /><path d="M12 14v3" /></>,
    plus: <><path d="M12 5v14" /><path d="M5 12h14" /></>,
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></>,
    upload: <><path d="M12 16V4" /><path d="m7 9 5-5 5 5" /><path d="M20 16.5v2.25A2.25 2.25 0 0 1 17.75 21h-11.5A2.25 2.25 0 0 1 4 18.75V16.5" /></>,
  };
  return <svg {...props}>{paths[name]}</svg>;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

function toBase64Url(bytes) {
  let binary = "";
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const blockSize = 0x8000;
  for (let offset = 0; offset < view.length; offset += blockSize) {
    binary += String.fromCharCode(...view.subarray(offset, offset + blockSize));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("The decryption key in this link is invalid.");
  }
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function makeNonce(prefix, chunkIndex) {
  const nonce = new Uint8Array(12);
  nonce.set(prefix);
  new DataView(nonce.buffer).setUint32(8, chunkIndex, false);
  return nonce;
}

function associatedData(transferId, fileId, chunkIndex) {
  return encoder.encode(`wormhole-v1:${transferId}:${fileId}:${chunkIndex}`);
}

function parseTransferIdFromPath() {
  const match = window.location.pathname.match(/^\/share\/([0-9a-f-]{36})\/?$/i);
  return match?.[1] ?? null;
}

function Brand() {
  return (
    <a className="brand" href="/" aria-label="Wormhole home">
      <span className="brand-icon" aria-hidden="true">
        <span className="brand-loop brand-loop-one" />
        <span className="brand-loop brand-loop-two" />
      </span>
      <span>wormhole</span>
    </a>
  );
}

function FileRow({ file, onRemove, disabled = false, as: Element = "li" }) {
  return (
    <Element className="file-row">
      <span className="file-icon"><Icon name="file" size={17} /></span>
      <span className="file-details"><strong title={file.name}>{file.name}</strong><small>{formatSize(file.size)}</small></span>
      {onRemove && (
        <button className="remove-file" type="button" aria-label={`Remove ${file.name}`} disabled={disabled} onClick={onRemove}>
          <Icon name="close" size={16} />
        </button>
      )}
    </Element>
  );
}

function SendPage() {
  const fileInput = useRef(null);
  const folderInput = useRef(null);
  const [files, setFiles] = useState([]);
  const [isDragging, setIsDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [shareUrl, setShareUrl] = useState("");
  const [copied, setCopied] = useState(false);
  const totalSize = files.reduce((total, file) => total + file.size, 0);

  function addFiles(fileList) {
    const incoming = Array.from(fileList || []);
    if (!incoming.length) return;
    setError("");
    setShareUrl("");
    setFiles((current) => {
      const knownFiles = new Set(current.map((file) => `${file.name}-${file.size}-${file.lastModified}`));
      const newFiles = incoming.filter((file) => {
        const key = `${file.name}-${file.size}-${file.lastModified}`;
        if (knownFiles.has(key)) return false;
        knownFiles.add(key);
        return true;
      });
      return [...current, ...newFiles].slice(0, MAX_FILES);
    });
  }

  function removeFile(index) {
    setFiles((current) => current.filter((_, fileIndex) => fileIndex !== index));
    setShareUrl("");
  }

  async function createTransfer() {
    if (busy || !files.length) return;
    if (files.length > MAX_FILES) {
      setError(`Choose no more than ${MAX_FILES} files.`);
      return;
    }
    if (totalSize > MAX_TRANSFER_BYTES) {
      setError("This transfer exceeds the 1 GiB limit.");
      return;
    }
    if (!window.crypto?.subtle || !window.isSecureContext) {
      setError("Secure encryption requires HTTPS or localhost and a browser with Web Crypto support.");
      return;
    }

    setBusy(true);
    setError("");
    setProgress(0);
    try {
      const createResponse = await fetch("/api/transfers", { method: "POST" });
      const created = await createResponse.json();
      if (!createResponse.ok) throw new Error(created.error || "Could not start the transfer.");

      const rawKey = crypto.getRandomValues(new Uint8Array(32));
      const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"]);
      const uploadHeaders = { Authorization: `Bearer ${created.uploadToken}`, "Content-Type": "application/octet-stream" };
      const metadataFiles = [];
      const plainChunks = files.reduce((total, file) => total + Math.ceil(file.size / CHUNK_SIZE), 0);
      let completedChunks = 0;

      for (const file of files) {
        const fileId = crypto.randomUUID();
        const noncePrefix = crypto.getRandomValues(new Uint8Array(8));
        const chunkCount = Math.ceil(file.size / CHUNK_SIZE);
        const metadata = {
          id: fileId,
          name: file.name,
          size: file.size,
          type: file.type || "application/octet-stream",
          lastModified: file.lastModified,
          noncePrefix: toBase64Url(noncePrefix),
          chunkCount,
        };
        metadataFiles.push(metadata);

        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
          const start = chunkIndex * CHUNK_SIZE;
          const plaintext = await file.slice(start, Math.min(start + CHUNK_SIZE, file.size)).arrayBuffer();
          const encrypted = await crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: makeNonce(noncePrefix, chunkIndex),
            additionalData: associatedData(created.id, fileId, chunkIndex),
          }, key, plaintext);
          const uploadResponse = await fetch(`/api/transfers/${created.id}/files/${fileId}/chunks/${chunkIndex}`, {
            method: "PUT",
            headers: uploadHeaders,
            body: encrypted,
          });
          if (!uploadResponse.ok) {
            const result = await uploadResponse.json();
            throw new Error(result.error || `Could not upload ${file.name}.`);
          }
          completedChunks += 1;
          setProgress(plainChunks ? Math.round((completedChunks / plainChunks) * 100) : 90);
        }
      }

      const manifest = {
        version: 1,
        transferId: created.id,
        files: metadataFiles,
      };
      const manifestIv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedManifest = await crypto.subtle.encrypt({
        name: "AES-GCM",
        iv: manifestIv,
        additionalData: encoder.encode(`wormhole-v1:${created.id}:manifest`),
      }, key, encoder.encode(JSON.stringify(manifest)));
      const completeResponse = await fetch(`/api/transfers/${created.id}/complete`, {
        method: "POST",
        headers: {
          ...uploadHeaders,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          files: metadataFiles.map(({ id, chunkCount }) => ({ id, chunkCount })),
          manifest: {
            iv: toBase64Url(manifestIv),
            ciphertext: toBase64Url(encryptedManifest),
          },
        }),
      });
      const completion = await completeResponse.json();
      if (!completeResponse.ok) throw new Error(completion.error || "Could not finish the transfer.");

      const link = new URL(`/share/${created.id}`, window.location.origin);
      link.hash = toBase64Url(rawKey);
      setShareUrl(link.toString());
      setProgress(100);
    } catch (transferError) {
      setError(transferError.message || "The transfer could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2200);
    } catch {
      setError("Could not copy the link. Select it and copy it manually.");
    }
  }

  return (
    <div className="page-shell">
      <header className="topbar">
        <Brand />
        <nav className="nav-links" aria-label="Main navigation">
          <a href="#how-it-works">How it works</a>
          <a href="#privacy">Privacy</a>
          <a href="https://wormhole.app/faq" target="_blank" rel="noreferrer">FAQ <span className="external-mark">↗</span></a>
        </nav>
        <a className="header-cta" href="#send-files">Send files <Icon name="arrow" size={16} /></a>
      </header>

      <main id="home">
        <section className="hero">
          <div className="hero-glow" />
          <div className="hero-copy">
            <span className="eyebrow"><span className="eyebrow-dot" /> A LITTLE MORE PRIVATE</span>
            <h1>Files have places<br />to <span>go.</span></h1>
            <p>Send files of any size, privately. No account, no clutter—just a link that gets your files where they need to be.</p>
            <div className="hero-points">
              <span><Icon name="lock" size={15} /> Encrypted in your browser</span>
              <span><Icon name="clock" size={15} /> Links expire after 24 hours</span>
            </div>
          </div>

          <section className="transfer-card" id="send-files" aria-labelledby="transfer-title">
            <div className="card-heading">
              <div><span className="card-eyebrow">YOUR PRIVATE PORTAL</span><h2 id="transfer-title">{shareUrl ? "Your link is ready" : "Send your files"}</h2></div>
              <span className="private-badge"><Icon name="lock" size={13} /> Private</span>
            </div>

            {shareUrl ? (
              <div className="share-result">
                <span className="share-ready"><Icon name="check" size={16} /> Encrypted transfer ready</span>
                <p>Share this link with your recipient. Keep it private: the link contains the decryption key.</p>
                <div className="share-link-box"><span>{shareUrl}</span></div>
                <button className="send-button" type="button" onClick={copyLink}>{copied ? "Link copied" : "Copy private link"} <Icon name={copied ? "check" : "link"} size={17} /></button>
                <p className="expiry-note"><Icon name="clock" size={14} /> This link expires in 24 hours.</p>
                <button className="new-transfer-button" type="button" onClick={() => { setFiles([]); setShareUrl(""); setProgress(0); }}>Start another transfer</button>
              </div>
            ) : (
              <>
                <div
                  className={`drop-zone${isDragging ? " dragging" : ""}${files.length ? " has-files" : ""}${busy ? " is-busy" : ""}`}
                  onDragOver={(event) => { event.preventDefault(); if (!busy) setIsDragging(true); }}
                  onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setIsDragging(false); }}
                  onDrop={(event) => {
                    event.preventDefault();
                    setIsDragging(false);
                    if (!busy) addFiles(event.dataTransfer.files);
                  }}
                >
                  <input ref={fileInput} className="visually-hidden" type="file" multiple disabled={busy} onChange={(event) => { addFiles(event.target.files); event.target.value = ""; }} />
                  <input ref={folderInput} className="visually-hidden" type="file" multiple webkitdirectory="" directory="" disabled={busy} onChange={(event) => { addFiles(event.target.files); event.target.value = ""; }} />

                  {files.length === 0 ? (
                    <div className="empty-drop">
                      <div className="upload-icon"><Icon name="upload" size={24} /></div>
                      <strong>Drop your files here</strong>
                      <span>or choose from your device</span>
                      <div className="file-actions">
                        <button className="choose-button" type="button" disabled={busy} onClick={() => fileInput.current?.click()}><Icon name="plus" size={16} /> Choose files</button>
                        <button className="folder-button" type="button" disabled={busy} onClick={() => folderInput.current?.click()}><Icon name="folder" size={16} /> Choose a folder</button>
                      </div>
                    </div>
                  ) : (
                    <div className="file-list-wrap">
                      <div className="file-list-heading">
                        <div><strong>{files.length} {files.length === 1 ? "file" : "files"} selected</strong><span>{formatSize(totalSize)} · 1 GiB max</span></div>
                        <button className="add-files-button" type="button" disabled={busy} onClick={() => fileInput.current?.click()}><Icon name="plus" size={15} /> Add more</button>
                      </div>
                      <ul className="file-list">{files.map((file, index) => <FileRow key={`${file.name}-${file.size}-${file.lastModified}-${index}`} file={file} disabled={busy} onRemove={() => removeFile(index)} />)}</ul>
                      <button className="add-folder-button" type="button" disabled={busy} onClick={() => folderInput.current?.click()}><Icon name="folder" size={15} /> Add a folder</button>
                    </div>
                  )}
                  {busy && (
                    <div className="upload-progress">
                      <div className="progress-label"><span>Encrypting &amp; uploading</span><span>{progress}%</span></div>
                      <div className="progress-track"><span style={{ width: `${progress}%` }} /></div>
                      <small>Keep this tab open until the transfer is complete.</small>
                    </div>
                  )}
                </div>

                <div className="transfer-options">
                  <div className="option-item">
                    <span className="option-icon"><Icon name="lock" size={16} /></span>
                    <span><strong>End-to-end encrypted</strong><small>Encryption key stays in the share link</small></span>
                    <span className="option-check"><Icon name="check" size={14} /></span>
                  </div>
                  <div className="option-item">
                    <span className="option-icon"><Icon name="clock" size={16} /></span>
                    <span><strong>Automatically expires</strong><small>Encrypted files are removed after 24 hours</small></span>
                    <span className="option-value">24 hours</span>
                  </div>
                </div>
                {error && <p className="transfer-error" role="alert">{error}</p>}
                <button className="send-button" type="button" disabled={!files.length || busy || totalSize > MAX_TRANSFER_BYTES} onClick={createTransfer}>
                  {busy ? "Encrypting and uploading…" : files.length ? <>Encrypt &amp; create link <Icon name="arrow" size={18} /></> : <>Select files to continue <Icon name="arrow" size={18} /></>}
                </button>
                <p className="card-footnote"><Icon name="shield" size={14} /> Up to 100 files · 1 GiB per transfer · no account</p>
              </>
            )}
          </section>

          <div className="hero-decoration decoration-one" /><div className="hero-decoration decoration-two" />
        </section>

        <section className="trust-strip" aria-label="Transfer security">
          <div className="trust-item"><span className="trust-icon"><Icon name="lock" size={18} /></span><span><strong>Encrypted on your device</strong><small>Files are encrypted before upload</small></span></div>
          <span className="trust-divider" />
          <div className="trust-item"><span className="trust-icon"><Icon name="link" size={18} /></span><span><strong>One private link</strong><small>The decryption key stays in its fragment</small></span></div>
          <span className="trust-divider" />
          <div className="trust-item"><span className="trust-icon"><Icon name="clock" size={18} /></span><span><strong>Gone in 24 hours</strong><small>Encrypted files are automatically deleted</small></span></div>
        </section>

        <section className="how-section" id="how-it-works">
          <div className="section-intro"><span className="card-eyebrow">NO DETOURS, JUST SEND</span><h2>Three steps.<br /><span>On their way.</span></h2></div>
          <div className="steps">
            <article className="step-card"><span className="step-number">01</span><span className="step-icon"><Icon name="upload" size={20} /></span><h3>Pick your files</h3><p>Drop in up to 100 files or choose a whole folder.</p></article>
            <article className="step-card"><span className="step-number">02</span><span className="step-icon"><Icon name="lock" size={20} /></span><h3>Encrypted on your device</h3><p>A fresh AES-GCM key encrypts file chunks before upload.</p></article>
            <article className="step-card"><span className="step-number">03</span><span className="step-icon"><Icon name="link" size={20} /></span><h3>Share the link</h3><p>Your recipient opens the link to decrypt and download each file.</p></article>
          </div>
        </section>

        <section className="privacy-note" id="privacy">
          <span className="privacy-icon"><Icon name="shield" size={21} /></span>
          <div><span className="card-eyebrow">PRIVATE FILES, PRIVATE KEYS</span><h2>The server only stores encrypted data.</h2><p>File names and types are encrypted. The server can infer approximate sizes and file counts from chunk data. The share-link key is never sent with API requests. Anyone with the link can access the transfer; this service does not hide network metadata or guarantee anonymity.</p></div>
          <a href="https://wormhole.app/faq" target="_blank" rel="noreferrer">Wormhole FAQ <Icon name="arrow" size={16} /></a>
        </section>
      </main>

      <footer className="footer"><Brand /><span className="footer-note">Send a little something, privately.</span><span className="footer-demo">Independent encrypted file-sharing app · Not the official Wormhole service</span></footer>
    </div>
  );
}

function ReceivePage({ transferId }) {
  const [encryptionKey, setEncryptionKey] = useState(() => window.location.hash.slice(1));
  const [files, setFiles] = useState([]);
  const [expiresAt, setExpiresAt] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [downloadingFile, setDownloadingFile] = useState("");
  const [downloadProgress, setDownloadProgress] = useState(0);

  useEffect(() => {
    let active = true;
    async function loadTransfer() {
      if (!encryptionKey) {
        setError("This link is missing its decryption key. Ask the sender to share the complete link.");
        setLoading(false);
        return;
      }
      try {
        if (!window.crypto?.subtle || !window.isSecureContext) throw new Error("Secure decryption requires HTTPS or localhost.");
        const rawKey = fromBase64Url(encryptionKey);
        if (rawKey.byteLength !== 32) throw new Error("This link contains an invalid decryption key.");
        const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const response = await fetch(`/api/transfers/${transferId}`);
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "This transfer is unavailable or has expired.");

        const manifestBytes = await crypto.subtle.decrypt({
          name: "AES-GCM",
          iv: fromBase64Url(result.manifest.iv),
          additionalData: encoder.encode(`wormhole-v1:${transferId}:manifest`),
        }, key, fromBase64Url(result.manifest.ciphertext));
        const manifest = JSON.parse(decoder.decode(manifestBytes));
        if (manifest.version !== 1 || manifest.transferId !== transferId || !Array.isArray(manifest.files) || manifest.files.length > MAX_FILES) {
          throw new Error("The encrypted file list is invalid.");
        }
        const listedFiles = new Map(result.files.map((file) => [file.id, file.chunkCount]));
        for (const file of manifest.files) {
          if (
            typeof file.id !== "string"
            || !/^[0-9a-f-]{36}$/i.test(file.id)
            || typeof file.name !== "string"
            || !Number.isSafeInteger(file.size)
            || file.size < 0
            || !Number.isInteger(file.chunkCount)
            || file.chunkCount !== Math.ceil(file.size / CHUNK_SIZE)
            || listedFiles.get(file.id) !== file.chunkCount
          ) {
            throw new Error("The encrypted file list is invalid.");
          }
          fromBase64Url(file.noncePrefix);
        }
        if (listedFiles.size !== manifest.files.length) throw new Error("The encrypted file list is invalid.");
        if (active) {
          setFiles(manifest.files);
          setExpiresAt(result.expiresAt);
        }
      } catch (loadError) {
        if (active) setError(loadError.message || "Could not open this transfer.");
      } finally {
        if (active) setLoading(false);
      }
    }
    loadTransfer();
    return () => { active = false; };
  }, [encryptionKey, transferId]);

  async function downloadFile(file) {
    if (downloadingFile) return;
    setDownloadingFile(file.id);
    setDownloadProgress(0);
    setError("");
    try {
      const rawKey = fromBase64Url(encryptionKey);
      const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
      const noncePrefix = fromBase64Url(file.noncePrefix);
      const parts = [];
      for (let chunkIndex = 0; chunkIndex < file.chunkCount; chunkIndex += 1) {
        const response = await fetch(`/api/transfers/${transferId}/files/${file.id}/chunks/${chunkIndex}`);
        if (!response.ok) throw new Error(`Could not download ${file.name}. The transfer may have expired.`);
        const encrypted = await response.arrayBuffer();
        const plaintext = await crypto.subtle.decrypt({
          name: "AES-GCM",
          iv: makeNonce(noncePrefix, chunkIndex),
          additionalData: associatedData(transferId, file.id, chunkIndex),
        }, key, encrypted);
        parts.push(plaintext);
        setDownloadProgress(Math.round(((chunkIndex + 1) / file.chunkCount) * 100));
      }

      const blob = new Blob(parts, { type: file.type || "application/octet-stream" });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = file.name;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
    } catch (downloadError) {
      setError(downloadError.message || "Could not decrypt this file.");
    } finally {
      setDownloadingFile("");
    }
  }

  return (
    <div className="page-shell receive-shell">
      <header className="topbar"><Brand /><a className="header-cta" href="/">Send files <Icon name="arrow" size={16} /></a></header>
      <main className="receive-main">
        <div className="receive-card">
          <span className="receive-lock"><Icon name="lock" size={23} /></span>
          <span className="card-eyebrow">A PRIVATE WORMHOLE LINK</span>
          <h1>{loading ? "Opening your files…" : error ? "This link needs a look." : "Files, delivered."}</h1>
          {loading && <p className="receive-subtitle">Checking the link and decrypting the file list in your browser.</p>}
          {error && <p className="receive-error" role="alert">{error}</p>}
          {!loading && !error && (
            <>
              <p className="receive-subtitle">{files.length} {files.length === 1 ? "file" : "files"} · Expires {new Date(expiresAt).toLocaleString()}</p>
              <ul className="file-list receive-file-list">
                {files.map((file) => (
                  <li className="receive-file-row" key={file.id}>
                    <FileRow file={file} as="div" />
                    <button className="download-button" type="button" disabled={Boolean(downloadingFile)} onClick={() => downloadFile(file)}>
                      {downloadingFile === file.id ? `${downloadProgress}%` : <>Download <Icon name="arrow" size={15} /></>}
                    </button>
                  </li>
                ))}
              </ul>
              {error && <p className="transfer-error" role="alert">{error}</p>}
              <p className="card-footnote"><Icon name="shield" size={14} /> Decryption happens in your browser. The server never receives the key.</p>
            </>
          )}
          <a className="receive-home-link" href="/">Send files of your own <Icon name="arrow" size={15} /></a>
        </div>
      </main>
      <footer className="footer receive-footer"><Brand /><span className="footer-demo">Independent encrypted file-sharing app · Not the official Wormhole service</span></footer>
    </div>
  );
}

function App() {
  const transferId = parseTransferIdFromPath();
  return transferId ? <ReceivePage transferId={transferId} /> : <SendPage />;
}

export default App;
