/** Host-only authenticated Principal and request-scoped context seam. */

import { AsyncLocalStorage } from 'node:async_hooks'
import { createHash } from 'node:crypto'
import { Context, Service } from '@deepseek-ai/cordis'
import type { Branded } from '@deepseek-ai/dsh-brand'

/** Stable identity derived exclusively from one verified OIDC issuer and subject. */
export type PrincipalId = Branded<'PrincipalId'>

/** Minimal verified identity projection exposed to Host business services. */
export interface Principal {
  readonly principalId: PrincipalId
  readonly issuer: string
  readonly subject: string
  readonly displayName?: string
  readonly email?: string
  readonly authenticatedAt: string
}

/** Authentication state bound to one HTTP request or WebSocket generation. */
export interface AuthenticatedPrincipalContext {
  readonly principal: Principal
  readonly expiresAt: number
  readonly invalidated: AbortSignal
  /** Provider-owned maximum delay between active-stream revalidation attempts. */
  readonly revalidateIntervalMs: number
  readonly sessionId?: string
}

/** Request facts accepted by a Host Principal provider. */
export interface PrincipalRequest {
  readonly headers: Headers | Readonly<Record<string, string | readonly string[] | undefined>>
  readonly method?: string | undefined
  readonly url?: string | undefined
}

/** Response operations used when an index request needs an authentication challenge. */
export interface PrincipalResponse {
  writeHead(status: number, headers?: Readonly<Record<string, string>>): unknown
  end(body?: string): unknown
}

/** Stable authentication failure categories safe to expose across Host transports. */
export type PrincipalFailureCode = 'principal-unauthenticated' | 'principal-unavailable'

/** Stable authentication failure with an HTTP status that contains no claims or tokens. */
export class PrincipalAuthenticationError extends Error {
  constructor(
    readonly code: PrincipalFailureCode,
    readonly status: 401 | 503,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options)
    this.name = 'PrincipalAuthenticationError'
  }
}

/** Provider seam implemented by OIDC or another deployment identity authority. */
export abstract class PrincipalProvider extends Service {
  constructor(ctx: Context) {
    super(ctx, 'principalProvider')
  }

  /**
   * Authenticate one Host request without trusting payload, query, or caller-supplied identity headers.
   * @param request - Host-derived request facts.
   * @returns the verified Principal context bound to this request.
   */
  abstract authenticate(request: PrincipalRequest): Promise<AuthenticatedPrincipalContext>

  /**
   * Authenticate an index request or own its login redirect/401 response.
   * @param request - Host-derived index request facts.
   * @param response - Host response used for redirects or failures.
   * @returns whether the caller may serve the requested index immediately.
   */
  abstract authorizeIndex(request: PrincipalRequest, response: PrincipalResponse): Promise<boolean>

  /**
   * Revalidate an active context; providers may rotate its invalidation signal on failure.
   * @param context - previously authenticated request or stream context.
   */
  revalidate(context: AuthenticatedPrincipalContext): Promise<void> {
    assertPrincipalContextActive(context)
    return Promise.resolve()
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Request-scoped authenticated Principal access. */
    principals: PrincipalContextService
    /** Optional deployment authentication provider. */
    principalProvider: PrincipalProvider
  }
}

/**
 * Derive an opaque id from the exact verified issuer, a NUL delimiter, and subject.
 * @param issuer - exact verified OIDC issuer.
 * @param subject - verified subject unique within the issuer.
 * @returns a stable opaque Principal identifier.
 */
export function derivePrincipalId(issuer: string, subject: string): PrincipalId {
  assertIdentityPart(issuer, 'issuer')
  assertIdentityPart(subject, 'subject')
  const digest = createHash('sha256').update(issuer).update('\0').update(subject).digest('base64url')
  return `oidc:v1:${digest}` as PrincipalId
}

/**
 * Build the immutable Principal projection after protocol-level claim validation succeeds.
 * @param input - protocol-verified identity claims and authentication time.
 * @returns an immutable minimal Principal projection.
 */
export function verifiedPrincipal(input: {
  issuer: string
  subject: string
  displayName?: string | undefined
  email?: string | undefined
  authenticatedAt?: string | undefined
}): Principal {
  const displayName = cleanOptional(input.displayName)
  const email = cleanOptional(input.email)
  const principal: Principal = {
    principalId: derivePrincipalId(input.issuer, input.subject),
    issuer: input.issuer,
    subject: input.subject,
    ...(displayName === undefined ? {} : { displayName }),
    ...(email === undefined ? {} : { email }),
    authenticatedAt: input.authenticatedAt ?? new Date().toISOString(),
  }
  return Object.freeze(principal)
}

/**
 * Fail closed when a context is absent, expired, or invalidated.
 * @param context - candidate authenticated context.
 * @param now - epoch milliseconds used for expiry comparison.
 * @returns after asserting that `context` is active.
 */
export function assertPrincipalContextActive(
  context: AuthenticatedPrincipalContext | undefined,
  now = Date.now(),
): asserts context is AuthenticatedPrincipalContext {
  if (context === undefined) {
    throw new PrincipalAuthenticationError('principal-unauthenticated', 401, 'authenticated Principal is required')
  }
  if (context.invalidated.aborted
    || !Number.isFinite(context.expiresAt)
    || context.expiresAt <= now
    || !Number.isSafeInteger(context.revalidateIntervalMs)
    || context.revalidateIntervalMs < 1
    || context.revalidateIntervalMs > 2_147_483_647) {
    throw new PrincipalAuthenticationError('principal-unauthenticated', 401, 'authenticated Principal is no longer active')
  }
}

/** AsyncLocalStorage-backed isolation for concurrent Host requests. */
export class PrincipalContextService extends Service {
  private readonly storage = new AsyncLocalStorage<AuthenticatedPrincipalContext>()

  constructor(ctx: Context) {
    super(ctx, 'principals')
  }

  /**
   * Run work inside one authenticated request context.
   * @param context - active Host-authenticated context.
   * @param callback - work that consumes the request-scoped Principal.
   * @returns the callback result.
   */
  run<T>(context: AuthenticatedPrincipalContext, callback: () => T): T {
    assertPrincipalContextActive(context)
    return this.storage.run(context, callback)
  }

  /**
   * Read the authenticated context without requiring one.
   * @returns the active context, or `undefined` outside authenticated work.
   */
  current(): AuthenticatedPrincipalContext | undefined {
    const context = this.storage.getStore()
    if (context === undefined) return undefined
    assertPrincipalContextActive(context)
    return context
  }

  /**
   * Require an active authenticated context.
   * @returns the active context, failing closed when none is usable.
   */
  require(): AuthenticatedPrincipalContext {
    const context = this.storage.getStore()
    assertPrincipalContextActive(context)
    return context
  }
}

function assertIdentityPart(value: string, label: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new TypeError(`Principal ${label} must be a non-empty string without NUL`)
  }
}

function cleanOptional(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const trimmed = value.trim()
  return trimmed === '' ? undefined : trimmed
}

export default PrincipalContextService
