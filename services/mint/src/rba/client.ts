/**
 * The subset of NovaVey/Relationship-Based-Authorization's HTTP API this
 * service needs — `POST /scope` and `POST /check`, per that repo's
 * docs/openapi.json and docs/INTEGRATION.md's "Bounding a delegation
 * credential's own scope" section (that section, and `/scope` itself,
 * were built for exactly this use case). RBA is a separate, sibling
 * service (HTTP-only; it exposes no importable library surface — see its
 * package.json), so this is a thin, hand-rolled client against its wire
 * contract, not a generated SDK.
 *
 * `RbaClient` is an interface, not a concrete class, so bounding.ts can
 * be tested against a fake without a live RBA instance — see
 * `rba/fake.ts`. `HttpRbaClient` below is the real implementation.
 */

export interface Subject {
  readonly ns: string;
  readonly id: string;
}

export interface NamespaceRelation {
  readonly namespace: string;
  readonly relationOrPermission: string;
}

export interface ScopeGrant {
  readonly namespace: string;
  readonly relationOrPermission: string;
  readonly granted: boolean;
  /** True only when granted is false and RBA's own candidate scan was
   * capped — "not found within what was scanned," not "confirmed
   * absent." Treat exactly like granted:false for bounding purposes:
   * never mint on an unconfirmed grant. */
  readonly truncated: boolean;
}

export interface ScopeGrantError {
  readonly namespace: string;
  readonly relationOrPermission: string;
  readonly error: { readonly code: string; readonly message: string };
}

export type ScopeGrantResult = ScopeGrant | ScopeGrantError;

export function isScopeGrantError(g: ScopeGrantResult): g is ScopeGrantError {
  return "error" in g;
}

export interface ScopeQueryResponse {
  readonly subject: Subject;
  readonly grants: readonly ScopeGrantResult[];
}

export interface CheckResponse {
  readonly allowed: boolean;
  readonly subject: Subject;
  readonly relation: string;
  readonly object: Subject;
  readonly depth: number;
}

/** RBA's own SCOPE_QUERY_MAX_TARGETS (src/audit/scope.ts in that repo) —
 * mirrored here as a client-side pre-check so an oversized request fails
 * fast with a clear reason instead of a round-trip to find out. */
export const SCOPE_QUERY_MAX_TARGETS = 50;

export interface RbaClient {
  /** POST /scope: for each (namespace, relationOrPermission) target, does
   * `subject` hold at least one grant anywhere in that namespace? Used to
   * bound a `scope` caveat triple whose resourceId is `'*'`. */
  scopeQuery(subject: Subject, targets: readonly NamespaceRelation[]): Promise<ScopeQueryResponse>;

  /** POST /check: is `subject` related to `object` via `relation`? Used
   * to bound a `scope` caveat triple with a specific resourceId. */
  check(subject: Subject, relation: string, object: Subject): Promise<CheckResponse>;
}

/** Thrown for any RBA call that didn't produce a usable answer: a network
 * failure, a timeout, a non-2xx response, or an unparsable body. Bounding
 * treats every one of these identically — fail closed, reject the mint —
 * per RBA's own documented recommendation ("treat an unreachable check
 * the same as a denied one," docs/INTEGRATION.md in that repo) extended
 * to every other way this call can fail to produce a real answer. */
export class RbaHttpError extends Error {
  readonly status?: number;
  readonly code?: string;

  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = "RbaHttpError";
    this.status = status;
    this.code = code;
  }
}

export interface HttpRbaClientOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  /** Default 5000ms. RBA is a synchronous dependency on the mint path;
   * a hung request must not hang minting indefinitely. */
  readonly timeoutMs?: number;
  /** Injectable for testing against a local mock server; defaults to the
   * global fetch. */
  readonly fetchImpl?: typeof fetch;
}

interface ApiErrorBody {
  readonly error?: { readonly code?: string; readonly message?: string };
}

export class HttpRbaClient implements RbaClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: HttpRbaClientOptions) {
    if (opts.baseUrl.length === 0) throw new RangeError("HttpRbaClient: baseUrl must not be empty");
    if (opts.apiKey.length === 0) throw new RangeError("HttpRbaClient: apiKey must not be empty");
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    // One AbortController/timer for the WHOLE operation, not just the
    // initial fetch() call: fetch()'s own promise resolves once headers
    // arrive, before the body has necessarily finished streaming in. If
    // the timer were cleared right after that, a slow body (a stalled
    // connection after headers, not just a slow connect) would never hit
    // the timeout — the timer has to keep running through res.text() too.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      let res: Response;
      try {
        res = await this.fetchImpl(`${this.baseUrl}${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${this.apiKey}`,
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (err) {
        const reason = (err as Error).name === "AbortError" ? `timed out after ${this.timeoutMs}ms` : (err as Error).message;
        throw new RbaHttpError(`RBA request to ${path} failed: ${reason}`);
      }

      let text: string;
      try {
        text = await res.text();
      } catch (err) {
        const reason = (err as Error).name === "AbortError" ? `timed out after ${this.timeoutMs}ms` : (err as Error).message;
        throw new RbaHttpError(`RBA response from ${path} could not be read: ${reason}`, res.status);
      }

      let json: unknown;
      try {
        json = text.length > 0 ? JSON.parse(text) : undefined;
      } catch {
        throw new RbaHttpError(`RBA response from ${path} was not valid JSON (status ${res.status})`, res.status);
      }

      if (!res.ok) {
        const errorBody = json as ApiErrorBody | undefined;
        const code = errorBody?.error?.code;
        const message = errorBody?.error?.message ?? `RBA ${path} returned HTTP ${res.status}`;
        throw new RbaHttpError(message, res.status, code);
      }

      return json as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async scopeQuery(subject: Subject, targets: readonly NamespaceRelation[]): Promise<ScopeQueryResponse> {
    if (targets.length === 0) {
      throw new RangeError("scopeQuery: targets must not be empty");
    }
    if (targets.length > SCOPE_QUERY_MAX_TARGETS) {
      throw new RangeError(`scopeQuery: ${targets.length} targets exceeds RBA's own max of ${SCOPE_QUERY_MAX_TARGETS}`);
    }
    return this.post<ScopeQueryResponse>("/scope", { subject, targets });
  }

  async check(subject: Subject, relation: string, object: Subject): Promise<CheckResponse> {
    return this.post<CheckResponse>("/check", { subject, relation, object });
  }
}
