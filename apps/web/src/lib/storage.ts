/**
 * Persistenza del vault in IndexedDB.
 *
 * Viene salvato **solo** il file cifrato prodotto dal core (`Session.seal()`):
 * nessun segreto, nome di account o metadato in chiaro tocca il disco.
 */

const DB_NAME = "authenticator";
const STORE = "vault";
const KEY = "current";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => {
      resolve(request.result);
    };
    request.onerror = () => {
      reject(request.error ?? new Error("IndexedDB non disponibile"));
    };
  });
}

async function transact<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest,
): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = run(tx.objectStore(STORE));
      tx.oncomplete = () => {
        resolve(request.result as T);
      };
      tx.onerror = () => {
        reject(tx.error ?? new Error("Transazione IndexedDB fallita"));
      };
    });
  } finally {
    db.close();
  }
}

/** Legge il vault cifrato, o `null` se non esiste ancora. */
export async function loadVault(): Promise<Uint8Array | null> {
  const value = await transact<unknown>("readonly", (s) => s.get(KEY));
  return value instanceof Uint8Array ? value : null;
}

/** Salva il vault cifrato sostituendo il precedente. */
export async function saveVault(sealed: Uint8Array): Promise<void> {
  await transact("readwrite", (s) => s.put(sealed, KEY));
}

/** Chiede al browser di non cancellare i dati in caso di poco spazio. */
export async function requestPersistence(): Promise<boolean> {
  if (!("storage" in navigator)) {
    return false;
  }
  return navigator.storage.persist();
}
