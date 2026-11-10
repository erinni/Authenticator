<script lang="ts">
  import { onDestroy } from "svelte";
  import { core, errorMessage } from "../lib/core";
  import { nowSeconds } from "../lib/format";
  import { friendlyError, importSummary } from "../lib/messages";
  import { grabFrame } from "../lib/qr-frame";
  import { SCREEN_CANCELLED, scanScreen } from "../lib/screen-scan";

  interface Props {
    onchange: () => Promise<void>;
  }
  const { onchange }: Props = $props();

  let video = $state<HTMLVideoElement>();
  let canvas = $state<HTMLCanvasElement>();
  let stream: MediaStream | null = null;
  let timer: ReturnType<typeof setInterval> | undefined;
  let scanning = $state(false);
  let status = $state<string | null>(null);
  let error = $state<string | null>(null);
  let capturing = $state(false);

  let busy = false;

  /** Analizza un fotogramma; restituisce `true` se ha trovato almeno un QR. */
  async function scan(source: CanvasImageSource, width: number, height: number): Promise<boolean> {
    if (!canvas || busy) {
      return false;
    }
    const frame = grabFrame(canvas, source, width, height);
    if (!frame) {
      return false;
    }
    busy = true;
    try {
      // I pixel vengono trasferiti al worker, che li azzera dopo l'analisi.
      const view = await core.scanQr(
        frame.width,
        frame.height,
        new Uint8Array(frame.data.buffer),
        nowSeconds(),
      );
      if (view.found === 0) {
        return false;
      }
      if (view.added + view.duplicates + view.skipped === 0) {
        status = "Il QR non contiene un account 2FA.";
        return true;
      }
      status = importSummary(view);
      if (view.added > 0) {
        await onchange();
      }
      return true;
    } finally {
      busy = false;
    }
  }

  async function startCamera() {
    error = null;
    status = null;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false,
      });
    } catch (e) {
      error = `Fotocamera non disponibile (${errorMessage(e)}).`;
      return;
    }
    scanning = true;
    await Promise.resolve();
    if (!video) {
      stopCamera();
      return;
    }
    const element = video;
    element.srcObject = stream;
    await element.play();
    timer = setInterval(() => {
      if (element.videoWidth > 0) {
        void scan(element, element.videoWidth, element.videoHeight).then((found) => {
          if (found) {
            stopCamera();
          }
        });
      }
    }, 300);
  }

  function stopCamera() {
    clearInterval(timer);
    for (const track of stream?.getTracks() ?? []) {
      track.stop();
    }
    stream = null;
    if (video) {
      video.srcObject = null;
    }
    scanning = false;
  }

  async function fromFile(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    if (!file) {
      return;
    }
    error = null;
    status = null;
    try {
      const bitmap = await createImageBitmap(file);
      const found = await scan(bitmap, bitmap.width, bitmap.height);
      bitmap.close();
      if (!found) {
        error = "Nessun QR code trovato nell'immagine.";
      }
    } catch (e) {
      error = friendlyError(errorMessage(e));
    }
  }

  async function fromScreen() {
    if (!scanScreen) {
      return;
    }
    error = null;
    status = null;
    capturing = true;
    try {
      const view = await scanScreen(nowSeconds());
      if (view.found === 0) {
        error = "Nessun QR code trovato sullo schermo: assicurati che sia visibile e riprova.";
      } else if (view.added + view.duplicates + view.skipped === 0) {
        status = "Il QR non contiene un account 2FA.";
      } else {
        status = importSummary(view);
        if (view.added > 0) {
          await onchange();
        }
      }
    } catch (e) {
      const message = errorMessage(e);
      if (message !== SCREEN_CANCELLED) {
        error = friendlyError(message);
      }
    } finally {
      capturing = false;
    }
  }

  onDestroy(stopCamera);
</script>

<section class="card">
  <h3>Scansiona un QR code</h3>
  <p class="hint">
    L'immagine viene analizzata solo su questo dispositivo e non viene salvata. Funziona anche con i
    QR di esportazione di Google Authenticator.
  </p>
  <div class="row">
    {#if scanScreen}
      <button onclick={fromScreen} disabled={capturing}>
        {capturing ? "Cattura in corso…" : "Scansiona dallo schermo"}
      </button>
    {/if}
    {#if scanning}
      <button class="ghost" onclick={stopCamera}>Ferma la fotocamera</button>
    {:else}
      <button onclick={startCamera}>Usa la fotocamera</button>
    {/if}
    <label class="file">
      <span>Da un'immagine…</span>
      <input type="file" accept="image/*" onchange={fromFile} />
    </label>
  </div>
  <video bind:this={video} class:hidden={!scanning} playsinline muted></video>
  <canvas bind:this={canvas} class="hidden"></canvas>
  {#if status}<p class="success" role="status">{status}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</section>
