<script lang="ts">
  import { onDestroy } from "svelte";
  import type { Session } from "../lib/core";
  import { errorMessage } from "../lib/core";
  import { nowSeconds } from "../lib/format";
  import { friendlyError, importSummary } from "../lib/messages";
  import { grabFrame } from "../lib/qr-frame";

  interface Props {
    session: Session;
    onchange: () => Promise<void>;
  }
  const { session, onchange }: Props = $props();

  interface ScanView {
    found: number;
    unsupported: number;
    added: number;
    duplicates: number;
    skipped: number;
  }

  let video = $state<HTMLVideoElement>();
  let canvas = $state<HTMLCanvasElement>();
  let stream: MediaStream | null = null;
  let timer: ReturnType<typeof setInterval> | undefined;
  let scanning = $state(false);
  let status = $state<string | null>(null);
  let error = $state<string | null>(null);

  /** Analizza un fotogramma; restituisce `true` se ha trovato almeno un QR utile. */
  function scan(source: CanvasImageSource, width: number, height: number): boolean {
    if (!canvas) {
      return false;
    }
    const frame = grabFrame(canvas, source, width, height);
    if (!frame) {
      return false;
    }
    const pixels = new Uint8Array(frame.data.buffer);
    try {
      const view = JSON.parse(
        session.scan_qr(frame.width, frame.height, pixels, nowSeconds()),
      ) as ScanView;
      if (view.found === 0) {
        return false;
      }
      if (view.added + view.duplicates + view.skipped === 0) {
        status = "Il QR non contiene un account 2FA.";
        return true;
      }
      status = importSummary(view);
      if (view.added > 0) {
        void onchange();
      }
      return true;
    } finally {
      pixels.fill(0);
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
      if (element.videoWidth > 0 && scan(element, element.videoWidth, element.videoHeight)) {
        stopCamera();
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
      const found = scan(bitmap, bitmap.width, bitmap.height);
      bitmap.close();
      if (!found) {
        error = "Nessun QR code trovato nell'immagine.";
      }
    } catch (e) {
      error = friendlyError(errorMessage(e));
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
