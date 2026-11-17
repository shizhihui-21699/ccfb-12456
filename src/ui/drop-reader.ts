/**
 * Reading workflow files out of a drag-and-drop payload.
 *
 * Dropping a *folder* from Finder/Explorer does not populate `dataTransfer
 * .files`; the entries live behind `webkitGetAsEntry`. This walks that tree and
 * returns only YAML files, so dropping `.github/workflows` works as expected.
 */

export interface DroppedFile {
  path: string;
  text: string;
}

const YAML_RE = /\.ya?ml$/i;
const MAX_BYTES = 512 * 1024;

interface FsEntry {
  isFile: boolean;
  isDirectory: boolean;
  name: string;
  fullPath?: string;
  file(onSuccess: (file: File) => void, onError: (err: unknown) => void): void;
  createReader(): {
    readEntries(onSuccess: (entries: FsEntry[]) => void, onError: (err: unknown) => void): void;
  };
}

async function readEntry(entry: FsEntry, prefix: string): Promise<DroppedFile[]> {
  if (entry.isFile) {
    return new Promise((resolve) => {
      entry.file(async (file) => {
        if (!YAML_RE.test(file.name) || file.size > MAX_BYTES) {
          resolve([]);
          return;
        }
        const text = await file.text();
        resolve([{ path: joinPath(prefix, file.name), text }]);
      }, () => resolve([]));
    });
  }

  if (entry.isDirectory && typeof entry.createReader === 'function') {
    const reader = entry.createReader();
    const children = await new Promise<FsEntry[]>((resolve) => {
      const all: FsEntry[] = [];
      const readBatch = () => {
        reader.readEntries(
          (batch) => {
            if (!batch.length) {
              resolve(all);
              return;
            }
            all.push(...batch);
            readBatch();
          },
          () => resolve(all),
        );
      };
      readBatch();
    });
    const nested = await Promise.all(children.map((child) => readEntry(child, joinPath(prefix, entry.name))));
    return nested.flat();
  }

  return Promise.resolve([]);
}

function joinPath(prefix: string, name: string): string {
  return prefix ? `${prefix}/${name}` : name;
}

/** Read every YAML file in a drop payload, using entries when available. */
export async function readDroppedFiles(dataTransfer: DataTransfer): Promise<DroppedFile[]> {
  const items = Array.from(dataTransfer.items ?? []).filter((i) => i.kind === 'file');
  const entries = items
    .map((item): FsEntry | null => {
      const withEntry = item as DataTransferItem & { webkitGetAsEntry?: () => unknown };
      return (withEntry.webkitGetAsEntry?.() as FsEntry | null | undefined) ?? null;
    })
    .filter((entry): entry is FsEntry => entry !== null);

  if (entries.length) {
    const results = await Promise.all(entries.map((entry) => readEntry(entry, '')));
    const files = results.flat();
    if (files.length || entries.every((e) => e.isDirectory)) return files;
  }

  // Fall back to plain files (older browsers, or a drop of loose files).
  const out: DroppedFile[] = [];
  for (const file of Array.from(dataTransfer.files ?? [])) {
    if (!YAML_RE.test(file.name) || file.size > MAX_BYTES) continue;
    out.push({ path: file.name, text: await file.text() });
  }
  return out;
}
