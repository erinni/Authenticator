/** Lato massimo dei fotogrammi analizzati: abbastanza per un QR, leggero da decodificare. */
export const MAX_FRAME_SIDE = 1024;

/** Dimensioni ridotte mantenendo le proporzioni. */
export function fitWithin(width: number, height: number, max = MAX_FRAME_SIDE): [number, number] {
  const scale = Math.min(1, max / Math.max(width, height));
  return [Math.max(1, Math.round(width * scale)), Math.max(1, Math.round(height * scale))];
}

/**
 * Disegna una sorgente (video o immagine) su un canvas ridotto e ne restituisce i pixel.
 * Il canvas viene poi ripulito, per non lasciare in memoria l'immagine del QR.
 */
export function grabFrame(
  canvas: HTMLCanvasElement,
  source: CanvasImageSource,
  width: number,
  height: number,
): ImageData | null {
  const [w, h] = fitWithin(width, height);
  canvas.width = w;
  canvas.height = h;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) {
    return null;
  }
  context.drawImage(source, 0, 0, w, h);
  const frame = context.getImageData(0, 0, w, h);
  context.clearRect(0, 0, w, h);
  return frame;
}
