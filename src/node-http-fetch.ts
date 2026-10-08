import { Buffer } from "node:buffer";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";

/**
 * A fetch-compatible transport over Node's own `http`/`https` modules.
 *
 * Acurast's iOS processor deprecates `httpPOST` and its global `fetch` rejects
 * with "fetch failed", while `https.request` reaches the network
 * (docs/raw/2026-10-08-ttof-js-lite-canary-no-first-contact.md in the
 * orchestrator). This adapter returns real HTTP statuses, so it sends no
 * response-tunnel header. It does not follow redirects: a 3xx comes back as-is.
 */
export function createNodeHttpFetch(): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> => {
    const request = nodeRequestLike(input);
    const url = new URL(request.url);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new TypeError(`Node HTTP fetch adapter does not support ${url.protocol} URLs`);
    }
    const method = (init?.method ?? request.method ?? "GET").toUpperCase();
    const headers = nodeHeaders(init?.headers ?? request.headers);
    const body = nodeBody(init?.body ?? null);
    if (body !== undefined && !hasHeader(headers, "content-length")) {
      headers["Content-Length"] = String(body.byteLength);
    }
    const signal = init?.signal ?? request.signal ?? undefined;
    if (signal?.aborted) throw abortError(signal);

    return new Promise<Response>((resolve, reject) => {
      const send = url.protocol === "https:" ? httpsRequest : httpRequest;
      let settled = false;
      const onAbort = () => {
        outgoing.destroy();
        fail(abortError(signal));
      };
      const fail = (error: unknown) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        reject(error);
      };
      const outgoing = send(url, { method, headers }, (incoming: IncomingMessage) => {
        const chunks: Buffer[] = [];
        incoming.on("data", (chunk: Buffer | string) => {
          chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
        });
        incoming.on("error", fail);
        incoming.on("end", () => {
          if (settled) return;
          settled = true;
          signal?.removeEventListener("abort", onAbort);
          const status = incoming.statusCode ?? 0;
          const bytes = Buffer.concat(chunks);
          resolve(
            new Response(NULL_BODY_STATUSES.has(status) ? null : bytes, {
              status,
              statusText: incoming.statusMessage ?? "",
              headers: responseHeaders(incoming)
            })
          );
        });
      });
      outgoing.on("error", fail);
      signal?.addEventListener("abort", onAbort, { once: true });
      if (body !== undefined) outgoing.write(body);
      outgoing.end();
    });
  }) as typeof fetch;
}

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

function nodeRequestLike(input: Parameters<typeof fetch>[0]): {
  url: string;
  method?: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
} {
  if (typeof input === "string") return { url: input };
  if (input instanceof URL) return { url: input.toString() };
  if (typeof Request === "function" && input instanceof Request) {
    return { url: input.url, method: input.method, headers: input.headers, signal: input.signal };
  }
  if (input && typeof input === "object" && "url" in input) {
    const like = input as { url?: unknown; method?: string; headers?: HeadersInit };
    return { url: String(like.url), method: like.method, headers: like.headers };
  }
  return { url: String(input) };
}

function nodeHeaders(headers: HeadersInit | undefined): Record<string, string> {
  if (!headers) return {};
  if (typeof Headers === "function" && headers instanceof Headers) return Object.fromEntries(headers.entries());
  if (Array.isArray(headers)) return Object.fromEntries(headers.map(([key, value]) => [key, String(value)]));
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, String(value)]));
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  return Object.keys(headers).some((key) => key.toLowerCase() === name);
}

function nodeBody(body: BodyInit | null): Buffer | undefined {
  if (body === null || body === undefined) return undefined;
  if (typeof body === "string") return Buffer.from(body, "utf8");
  if (body instanceof URLSearchParams) return Buffer.from(body.toString(), "utf8");
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  throw new Error("Node HTTP fetch adapter only supports string, Uint8Array, ArrayBuffer and URLSearchParams request bodies");
}

function responseHeaders(incoming: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(incoming.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
    } else {
      headers.set(key, value);
    }
  }
  return headers;
}

function abortError(signal: AbortSignal | undefined): Error {
  const reason = signal?.reason;
  if (reason instanceof Error && reason.name === "AbortError") return reason;
  const error = new Error("The operation was aborted");
  error.name = "AbortError";
  return error;
}
