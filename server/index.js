import express from "express";
import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createReadStream } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const port = Number(process.env.PORT) || 3001;
const root = path.dirname(fileURLToPath(import.meta.url));
const storagePath = path.join(root, "data", "encrypted-transfers");
const TRANSFER_LIFETIME_MS = 24 * 60 * 60 * 1000;
const CHUNK_SIZE = 4 * 1024 * 1024;
const MAX_TRANSFER_BYTES = 1024 * 1024 * 1024;
const MAX_FILES = 100;
const MAX_CHUNKS_PER_FILE = Math.ceil(MAX_TRANSFER_BYTES / CHUNK_SIZE);
const MAX_TOTAL_CHUNKS = MAX_CHUNKS_PER_FILE + MAX_FILES;
const MAX_CHUNK_BYTES = CHUNK_SIZE + 16;
const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fileLocks = new Map();

app.disable("x-powered-by");
app.use((_request, response, next) => {
  response.set({
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  next();
});
app.use(express.json({ limit: "1mb" }));

function transferDirectory(id) {
  return path.join(storagePath, id);
}

function tokenDigest(token) {
  return createHash("sha256").update(token).digest("hex");
}

function isValidId(value) {
  return typeof value === "string" && idPattern.test(value);
}

async function writeJsonAtomically(filePath, value) {
  const temporaryPath = `${filePath}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporaryPath, `${JSON.stringify(value)}\n`, { flag: "wx", mode: 0o600 });
    await rename(temporaryPath, filePath);
  } catch (error) {
    await rm(temporaryPath, { force: true });
    throw error;
  }
}

async function readTransfer(id) {
  if (!isValidId(id)) return null;
  try {
    const contents = await readFile(path.join(transferDirectory(id), "metadata.json"), "utf8");
    const transfer = JSON.parse(contents);
    if (Date.parse(transfer.expiresAt) <= Date.now()) {
      await rm(transferDirectory(id), { recursive: true, force: true });
      return null;
    }
    return transfer;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function withTransferLock(id, operation) {
  const previous = fileLocks.get(id) ?? Promise.resolve();
  let release;
  const lock = new Promise((resolve) => { release = resolve; });
  fileLocks.set(id, lock);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (fileLocks.get(id) === lock) fileLocks.delete(id);
  }
}

function authorized(request, transfer) {
  const token = request.get("authorization")?.match(/^Bearer ([0-9a-f]{64})$/i)?.[1];
  if (!token || !transfer.uploadTokenHash) return false;
  const supplied = Buffer.from(tokenDigest(token), "hex");
  const expected = Buffer.from(transfer.uploadTokenHash, "hex");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function errorResponse(response, status, message) {
  return response.status(status).json({ error: message });
}

function isValidManifest(manifest) {
  return manifest
    && typeof manifest.iv === "string"
    && /^[A-Za-z0-9_-]{16}$/.test(manifest.iv)
    && typeof manifest.ciphertext === "string"
    && /^[A-Za-z0-9_-]+$/.test(manifest.ciphertext)
    && manifest.ciphertext.length <= 1_400_000;
}

app.get("/api/health", (_request, response) => {
  response.json({
    status: "ok",
    encryption: "client-side AES-GCM",
    maxTransferBytes: MAX_TRANSFER_BYTES,
    maxFiles: MAX_FILES,
    expiresAfterHours: 24,
  });
});

app.post("/api/transfers", async (_request, response, next) => {
  try {
    const id = randomUUID();
    const uploadToken = randomBytes(32).toString("hex");
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + TRANSFER_LIFETIME_MS).toISOString();
    const directory = transferDirectory(id);
    await mkdir(path.join(directory, "chunks"), { recursive: true, mode: 0o700 });
    const transfer = {
      id,
      createdAt: createdAt.toISOString(),
      expiresAt,
      receivedBytes: 0,
      receivedChunks: 0,
      uploadTokenHash: tokenDigest(uploadToken),
      uploadedChunks: {},
      finalized: false,
    };
    await writeJsonAtomically(path.join(directory, "metadata.json"), transfer);
    response.status(201).json({ id, uploadToken, expiresAt });
  } catch (error) {
    next(error);
  }
});

app.put(
  "/api/transfers/:id/files/:fileId/chunks/:chunkIndex",
  express.raw({ type: "application/octet-stream", limit: MAX_CHUNK_BYTES }),
  async (request, response, next) => {
    const { id, fileId, chunkIndex: rawIndex } = request.params;
    const index = Number(rawIndex);
    if (!isValidId(id) || !isValidId(fileId) || !/^(0|[1-9]\d*)$/.test(rawIndex) || !Number.isSafeInteger(index) || index >= MAX_CHUNKS_PER_FILE) {
      return errorResponse(response, 400, "Invalid transfer or chunk identifier.");
    }
    if (!Buffer.isBuffer(request.body) || request.body.length < 17 || request.body.length > MAX_CHUNK_BYTES) {
      return errorResponse(response, 400, "Encrypted chunks must be between 17 bytes and 4 MiB plus 16 bytes.");
    }

    try {
      const result = await withTransferLock(id, async () => {
        const transfer = await readTransfer(id);
        if (!transfer) return { status: 404, error: "Transfer not found or expired." };
        if (!authorized(request, transfer)) return { status: 401, error: "Upload authorization failed." };
        if (transfer.finalized) return { status: 409, error: "This transfer has already been finalized." };

        const receivedForFile = transfer.uploadedChunks[fileId] ?? [];
        if (receivedForFile.includes(index)) return { status: 409, error: "This chunk was already uploaded." };
        if (!transfer.uploadedChunks[fileId] && Object.keys(transfer.uploadedChunks).length >= MAX_FILES) {
          return { status: 413, error: `A transfer can contain at most ${MAX_FILES} files.` };
        }
        if (transfer.receivedChunks >= MAX_TOTAL_CHUNKS) {
          return { status: 413, error: "The transfer contains too many chunks." };
        }
        const maxStoredBytes = MAX_TRANSFER_BYTES + MAX_TOTAL_CHUNKS * 16;
        if (transfer.receivedBytes + request.body.length > maxStoredBytes) {
          return { status: 413, error: "This transfer exceeds the 1 GiB limit." };
        }

        const fileDirectory = path.join(transferDirectory(id), "chunks", fileId);
        await mkdir(fileDirectory, { recursive: true, mode: 0o700 });
        const chunkPath = path.join(fileDirectory, `${index}.bin`);
        await writeFile(chunkPath, request.body, { flag: "wx", mode: 0o600 });
        const updated = {
          ...transfer,
          receivedBytes: transfer.receivedBytes + request.body.length,
          receivedChunks: transfer.receivedChunks + 1,
          uploadedChunks: {
            ...transfer.uploadedChunks,
            [fileId]: [...receivedForFile, index],
          },
        };
        try {
          await writeJsonAtomically(path.join(transferDirectory(id), "metadata.json"), updated);
        } catch (error) {
          await rm(chunkPath, { force: true });
          throw error;
        }
        return { status: 201 };
      });

      if (result.error) return errorResponse(response, result.status, result.error);
      return response.sendStatus(result.status);
    } catch (error) {
      return next(error);
    }
  },
);

app.post("/api/transfers/:id/complete", async (request, response, next) => {
  const { id } = request.params;
  if (!isValidId(id)) return errorResponse(response, 400, "Invalid transfer identifier.");
  const { files, manifest } = request.body ?? {};
  if (!Array.isArray(files) || files.length < 1 || files.length > MAX_FILES || !isValidManifest(manifest)) {
    return errorResponse(response, 400, "A valid encrypted manifest and 1–100 files are required.");
  }

  const seen = new Set();
  let totalChunks = 0;
  for (const file of files) {
    if (
      !file
      || !isValidId(file.id)
      || !Number.isInteger(file.chunkCount)
      || file.chunkCount < 0
      || file.chunkCount > MAX_CHUNKS_PER_FILE
      || seen.has(file.id)
    ) {
      return errorResponse(response, 400, "The encrypted file list is invalid.");
    }
    seen.add(file.id);
    totalChunks += file.chunkCount;
  }
  if (totalChunks > MAX_TOTAL_CHUNKS) return errorResponse(response, 413, "The transfer contains too many chunks.");

  try {
    const result = await withTransferLock(id, async () => {
      const transfer = await readTransfer(id);
      if (!transfer) return { status: 404, error: "Transfer not found or expired." };
      if (!authorized(request, transfer)) return { status: 401, error: "Upload authorization failed." };
      if (transfer.finalized) return { status: 409, error: "This transfer has already been finalized." };

      const nonEmptyFiles = files.filter((file) => file.chunkCount > 0);
      const uploadedIds = Object.keys(transfer.uploadedChunks);
      if (nonEmptyFiles.length !== uploadedIds.length) {
        return { status: 400, error: "Some encrypted file chunks are missing." };
      }

      for (const file of nonEmptyFiles) {
        const uploaded = transfer.uploadedChunks[file.id];
        if (!uploaded || uploaded.length !== file.chunkCount) {
          return { status: 400, error: "Some encrypted file chunks are missing." };
        }
        for (let index = 0; index < file.chunkCount; index += 1) {
          if (!uploaded.includes(index)) return { status: 400, error: "Some encrypted file chunks are missing." };
          try {
            await stat(path.join(transferDirectory(id), "chunks", file.id, `${index}.bin`));
          } catch (error) {
            if (error.code === "ENOENT") return { status: 400, error: "Some encrypted file chunks are missing." };
            throw error;
          }
        }
      }

      await writeJsonAtomically(path.join(transferDirectory(id), "manifest.json"), {
        manifest,
        files,
      });
      await writeJsonAtomically(path.join(transferDirectory(id), "metadata.json"), {
        ...transfer,
        finalized: true,
        uploadTokenHash: null,
        uploadedChunks: {},
        receivedChunks: 0,
      });
      return { status: 200, expiresAt: transfer.expiresAt };
    });

    if (result.error) return errorResponse(response, result.status, result.error);
    return response.json({ status: "ready", expiresAt: result.expiresAt });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/transfers/:id", async (request, response, next) => {
  try {
    const { id } = request.params;
    if (!isValidId(id)) return errorResponse(response, 404, "Transfer not found or expired.");
    const transfer = await readTransfer(id);
    if (!transfer || !transfer.finalized) return errorResponse(response, 404, "Transfer not found or expired.");
    const contents = await readFile(path.join(transferDirectory(id), "manifest.json"), "utf8");
    const { manifest, files } = JSON.parse(contents);
    return response.json({ expiresAt: transfer.expiresAt, manifest, files });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/transfers/:id/files/:fileId/chunks/:chunkIndex", async (request, response, next) => {
  try {
    const { id, fileId, chunkIndex: rawIndex } = request.params;
    const index = Number(rawIndex);
    if (!isValidId(id) || !isValidId(fileId) || !/^(0|[1-9]\d*)$/.test(rawIndex) || !Number.isSafeInteger(index)) {
      return errorResponse(response, 404, "Encrypted chunk not found.");
    }
    const transfer = await readTransfer(id);
    if (!transfer || !transfer.finalized) return errorResponse(response, 404, "Transfer not found or expired.");
    const contents = await readFile(path.join(transferDirectory(id), "manifest.json"), "utf8");
    const { files } = JSON.parse(contents);
    const file = files.find((item) => item.id === fileId);
    if (!file || index >= file.chunkCount) return errorResponse(response, 404, "Encrypted chunk not found.");
    const chunkPath = path.join(transferDirectory(id), "chunks", fileId, `${index}.bin`);
    const chunkStat = await stat(chunkPath);
    response.type("application/octet-stream");
    response.set("Content-Length", String(chunkStat.size));
    return createReadStream(chunkPath).pipe(response);
  } catch (error) {
    if (error.code === "ENOENT") return errorResponse(response, 404, "Encrypted chunk not found.");
    return next(error);
  }
});

async function removeExpiredTransfers() {
  await mkdir(storagePath, { recursive: true, mode: 0o700 });
  const entries = await readdir(storagePath, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory() || !isValidId(entry.name)) continue;
    try {
      const metadata = JSON.parse(await readFile(path.join(transferDirectory(entry.name), "metadata.json"), "utf8"));
      if (Date.parse(metadata.expiresAt) <= Date.now()) {
        await rm(transferDirectory(entry.name), { recursive: true, force: true });
      }
    } catch (error) {
      if (error.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error;
      if (error instanceof SyntaxError) {
        console.error(`Could not parse transfer metadata for ${entry.name}.`);
      }
    }
  }
}

await removeExpiredTransfers();
const cleanupTimer = setInterval(() => {
  removeExpiredTransfers().catch((error) => console.error("Transfer expiry cleanup failed:", error));
}, 60 * 60 * 1000);
cleanupTimer.unref();

app.use(express.static(path.resolve(root, "../dist")));
app.get("/{*path}", (_request, response, next) => {
  response.sendFile(path.resolve(root, "../dist/index.html"), (error) => {
    if (error) next(error);
  });
});

app.use((error, _request, response, _next) => {
  console.error(error);
  if (error.type === "entity.too.large") return errorResponse(response, 413, "Encrypted chunk is too large.");
  return errorResponse(response, 500, "The server could not complete the request.");
});

app.listen(port, () => {
  console.log(`Encrypted file transfer server listening on http://localhost:${port}`);
});
