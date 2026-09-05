/**
 * Runtime-neutral file I/O for the CLI.
 *
 * The CLI ships to npm as a Node program (`npx @forestrie/forestrie-cli`)
 * as well as a Bun-compiled static binary, so nothing under `src/` may
 * reach for `Bun.*`. These helpers are the `node:fs` equivalents of the
 * `Bun.file` / `Bun.write` / `Bun.stdin` calls the commands used to make,
 * with the one behaviour that was load-bearing preserved: `Bun.write`
 * creates missing parent directories, `fs.writeFile` does not.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

/** True for a `node:fs` "no such file or directory" rejection. */
function isNotFound(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { code?: unknown }).code === "ENOENT"
  );
}

/**
 * Write `data` to `filePath`, creating parent directories first
 * (`Bun.write` parity — several commands write into `--out` paths whose
 * directory the caller has not made).
 */
export async function writeOutputFile(
  filePath: string,
  data: string | Uint8Array,
): Promise<void> {
  const dir = path.dirname(path.resolve(filePath));
  await mkdir(dir, { recursive: true });
  await writeFile(filePath, data);
}

/**
 * Read `filePath` as UTF-8, raising `notFoundMessage` (not a raw ENOENT)
 * when it does not exist — the message flags surface to the user.
 */
export async function readTextFile(
  filePath: string,
  notFoundMessage: string,
): Promise<string> {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (isNotFound(error)) {
      throw new Error(notFoundMessage);
    }
    throw error;
  }
}

/** As `readTextFile`, but returns the raw bytes. */
export async function readBytesFile(
  filePath: string,
  notFoundMessage: string,
): Promise<Uint8Array> {
  try {
    const buffer = await readFile(filePath);
    return new Uint8Array(
      buffer.buffer,
      buffer.byteOffset,
      buffer.byteLength,
    );
  } catch (error) {
    if (isNotFound(error)) {
      throw new Error(notFoundMessage);
    }
    throw error;
  }
}

/** Drain stdin to bytes (`Bun.stdin.arrayBuffer()` equivalent). */
export async function readStdinBytes(): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(
      typeof chunk === "string" ? Buffer.from(chunk) : new Uint8Array(chunk),
    );
  }
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}
