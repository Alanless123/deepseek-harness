/** Host-only OpenID Connect implementation of the authenticated Principal seam. */

import { createHash, randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type {} from '@deepseek-ai/dsh-host-webserver'
import {
  PrincipalAuthenticationError,
  PrincipalProvider,
  assertPrincipalContextActive,
  verifiedPrincipal,
  type AuthenticatedPrincipalContext,
  type PrincipalRequest,
  type PrincipalResponse,
} from '@deepseek-ai/dsh-principal'
import { createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWTPayload } from 'jose'
import {
  ClientError,
  ClientSecretPost,
  None,
  ResponseBodyError,
  allowInsecureRequests,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  buildEndSessionUrl,
  calculatePKCECodeChallenge,
  discovery,
  enableNonRepudiationChecks,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
  tokenIntrospection,
  type Configuration,
  type IDToken,
  type IntrospectionResponse,
} from 'openid-client'
import {
  HTTP_REQUEST_FORBIDDEN,
  REQUEST_PROTOCOL_FORBIDDEN,
  RESPONSE_IS_NOT_CONFORM,
  RESPONSE_IS_NOT_JSON,
} from 'oauth4webapi'

const SESSION_COOKIE = 'dsh_oidc_session'
const TRANSACTION_COOKIE = 'dsh_oidc_transaction'
const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout'
const DEFAULT_LOGOUT_PATH = '/.dsh/oidc/logout'
const DEFAULT_BACKCHANNEL_LOGOUT_PATH = '/.dsh/oidc/backchannel-logout'
const MAX_BACKCHANNEL_BODY_BYTES = 16 * 1024
const CLOCK_TOLERANCE_SECONDS = 30
const BACKCHANNEL_MAX_AGE_SECONDS = 5 * 60
const BACKCHANNEL_REPLAY_RETENTION_SECONDS = BACKCHANNEL_MAX_AGE_SECONDS + CLOCK_TOLERANCE_SECONDS + 1
const MAX_REVALIDATE_INTERVAL_SECONDS = 60
const MIN_STREAM_REVALIDATE_INTERVAL_MS = 1_000
const MAX_LOGOUT_TOKEN_IDS = 20_000
const MAX_LOGOUT_TARGET_TOMBSTONES = 20_000

/** OIDC client and in-memory Host session configuration. */
export interface Config {
  /** Exact OIDC Issuer Identifier used for discovery and Principal identity. */
  issuer: string
  /** Registered OIDC client identifier. */
  clientId: string
  /** Exact resource-server audience required on every active access token. */
  accessTokenAudience: string
  /** Confidential-client secret. Omit for a public PKCE client. */
  clientSecret?: string
  /** Exact registered Authorization Code callback URI. */
  redirectUri: string
  /** Exact registered post-logout URI; defaults to the redirect URI origin. */
  postLogoutRedirectUri?: string
  /** Requested OIDC scopes. `openid` is always required. */
  scopes?: string[]
  /** ID Token and back-channel logout JWS algorithm. */
  signingAlgorithm?: string
  /** Cache duration before active access tokens are introspected again. */
  revalidateIntervalSeconds?: number
  /** Absolute Host session cap, independent of token expiration. */
  sessionMaxAgeSeconds?: number
  /** One-time state/nonce/PKCE transaction lifetime. */
  transactionTtlSeconds?: number
  /** Maximum active Host sessions retained in memory. */
  maxSessions?: number
  /** Maximum pending login transactions retained in memory. */
  maxTransactions?: number
  /** Browser route that starts RP-initiated logout. */
  logoutPath?: string
  /** IdP route for signed back-channel logout tokens. */
  backchannelLogoutPath?: string
  /** Explicitly permit HTTP only for a loopback development issuer and app. */
  allowInsecureHttp?: boolean
}

export const Config: z<Config> = z.object({
  issuer: z.string().required(),
  clientId: z.string().required(),
  accessTokenAudience: z.string().required(),
  clientSecret: z.string().role('secret'),
  redirectUri: z.string().required(),
  postLogoutRedirectUri: z.string(),
  scopes: z.array(z.string()).default(['openid', 'profile', 'email']),
  signingAlgorithm: z.string().default('RS256'),
  revalidateIntervalSeconds: z.natural().max(MAX_REVALIDATE_INTERVAL_SECONDS).default(15),
  sessionMaxAgeSeconds: z.natural().min(60).default(8 * 60 * 60),
  transactionTtlSeconds: z.natural().min(30).default(5 * 60),
  maxSessions: z.natural().min(1).default(10_000),
  maxTransactions: z.natural().min(1).default(1_024),
  logoutPath: z.string().default(DEFAULT_LOGOUT_PATH),
  backchannelLogoutPath: z.string().default(DEFAULT_BACKCHANNEL_LOGOUT_PATH),
  allowInsecureHttp: z.boolean().default(false),
})

interface ResolvedConfig {
  readonly issuer: string
  readonly issuerUrl: URL
  readonly clientId: string
  readonly accessTokenAudience: string
  readonly clientSecret?: string
  readonly redirectUri: URL
  readonly postLogoutRedirectUri: URL
  readonly scopes: readonly string[]
  readonly signingAlgorithm: string
  readonly revalidateIntervalMs: number
  readonly sessionMaxAgeMs: number
  readonly transactionTtlMs: number
  readonly maxSessions: number
  readonly maxTransactions: number
  readonly callbackPath: string
  readonly logoutPath: string
  readonly backchannelLogoutPath: string
  readonly secureCookies: boolean
  readonly allowInsecureHttp: boolean
}

interface LoginTransaction {
  readonly state: string
  readonly nonce: string
  readonly codeVerifier: string
  readonly returnTo: string
  readonly expiresAt: number
}

interface SessionRecord {
  readonly context: AuthenticatedPrincipalContext
  readonly controller: AbortController
  readonly accessToken: string
  readonly subject: string
  readonly sid?: string
  lastValidatedAt: number
  revalidating?: Promise<void>
}

interface OidcResponse extends PrincipalResponse {
  setHeader?(name: string, value: string | readonly string[]): unknown
}

interface BackchannelLogoutClaims extends JWTPayload {
  readonly sid?: string
  readonly events?: Record<string, unknown>
  readonly nonce?: unknown
}

interface LogoutTargetTombstone {
  readonly issuedAt: number
  readonly expiresAt: number
}

/** Stable Cordis plugin name. */
export const name = 'principal-oidc'
export const inject = ['webServer']

/** OIDC provider with one-time PKCE transactions and process-local opaque sessions. */
export class OidcPrincipalProvider extends PrincipalProvider {
  private readonly sessions = new Map<string, SessionRecord>()
  private readonly transactions = new Map<string, LoginTransaction>()
  private readonly logoutTokenIds = new Map<string, number>()
  private readonly logoutTargets = new Map<string, LogoutTargetTombstone>()
  private readonly logoutKeys

  private constructor(
    ctx: Context,
    private readonly options: ResolvedConfig,
    private readonly oidc: Configuration,
    jwksUri: URL,
  ) {
    super(ctx)
    this.logoutKeys = createRemoteJWKSet(jwksUri, { timeoutDuration: 10_000 })
    ctx.effect(() => () => {
      for (const sessionId of [...this.sessions.keys()]) this.revokeSession(sessionId, 'OIDC provider stopped')
      this.transactions.clear()
      this.logoutTokenIds.clear()
      this.logoutTargets.clear()
    }, 'principal-oidc: in-memory identity state')
  }

  /**
   * Discover and validate one OIDC issuer before registering the Principal service.
   * @param ctx - Cordis context that owns the provider lifecycle.
   * @param input - exact issuer, client, route, and session settings.
   * @returns the initialized Principal Provider.
   */
  static async create(ctx: Context, input: Config): Promise<OidcPrincipalProvider> {
    const options = resolveConfig(input)
    const clientAuthentication = options.clientSecret === undefined
      ? None()
      : ClientSecretPost(options.clientSecret)
    const execute: ((configuration: Configuration) => void)[] = [enableNonRepudiationChecks]
    if (options.allowInsecureHttp) {
      // oxlint-disable-next-line typescript/no-deprecated -- Explicitly gated to loopback development URLs above.
      execute.push(allowInsecureRequests)
    }
    const oidc = await discovery(
      options.issuerUrl,
      options.clientId,
      {
        redirect_uris: [options.redirectUri.href],
        response_types: ['code'],
        token_endpoint_auth_method: options.clientSecret === undefined ? 'none' : 'client_secret_post',
        id_token_signed_response_alg: options.signingAlgorithm,
      },
      clientAuthentication,
      { execute },
    )
    const metadata = oidc.serverMetadata()
    if (metadata.issuer !== options.issuer) {
      throw new Error('OIDC discovery returned a different issuer')
    }
    requireMetadataUrl(metadata.authorization_endpoint, 'authorization_endpoint', options)
    requireMetadataUrl(metadata.token_endpoint, 'token_endpoint', options)
    requireMetadataUrl(metadata.introspection_endpoint, 'introspection_endpoint', options)
    const jwksUri = requireMetadataUrl(metadata.jwks_uri, 'jwks_uri', options)
    if (metadata.end_session_endpoint !== undefined) {
      requireMetadataUrl(metadata.end_session_endpoint, 'end_session_endpoint', options)
    }
    return new OidcPrincipalProvider(ctx, options, oidc, jwksUri)
  }

  /** Authenticate an opaque Host session cookie and periodically introspect it. */
  override async authenticate(request: PrincipalRequest): Promise<AuthenticatedPrincipalContext> {
    this.assertApplicationAuthority(request)
    const sessionId = cookieValue(request.headers, SESSION_COOKIE)
    if (sessionId === undefined || !isOpaqueId(sessionId)) throw unauthenticated()
    const session = this.sessions.get(sessionId)
    if (session === undefined) throw unauthenticated()
    try {
      assertPrincipalContextActive(session.context)
    } catch (error) {
      this.revokeSession(sessionId, 'OIDC session expired')
      throw error
    }
    await this.revalidateSession(sessionId, session, false)
    return session.context
  }

  /** Serve an authenticated index or begin a state/nonce/PKCE authorization request. */
  override async authorizeIndex(request: PrincipalRequest, response: PrincipalResponse): Promise<boolean> {
    try {
      await this.authenticate(request)
      return true
    } catch (error) {
      if (!(error instanceof PrincipalAuthenticationError)) {
        writeUnavailable(response)
        return false
      }
      if (error.status === 503) {
        writeUnavailable(response)
        return false
      }
    }

    try {
      const target = this.applicationUrl(request)
      const transactionId = opaqueId()
      const codeVerifier = randomPKCECodeVerifier()
      const state = randomState()
      const nonce = randomNonce()
      const codeChallenge = await calculatePKCECodeChallenge(codeVerifier)
      this.cleanupTransactions()
      this.makeRoom(this.transactions, this.options.maxTransactions)
      this.transactions.set(transactionId, {
        state,
        nonce,
        codeVerifier,
        returnTo: safeReturnTo(target, this.options),
        expiresAt: Date.now() + this.options.transactionTtlMs,
      })
      const location = buildAuthorizationUrl(this.oidc, {
        redirect_uri: this.options.redirectUri.href,
        scope: this.options.scopes.join(' '),
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
        nonce,
      })
      response.writeHead(302, {
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
        location: location.href,
        'set-cookie': serializeCookie(
          TRANSACTION_COOKIE,
          transactionId,
          this.options.transactionTtlMs,
          this.options.callbackPath,
          this.options.secureCookies,
        ),
      })
      response.end()
    } catch {
      writeUnavailable(response)
    }
    return false
  }

  /** Revalidate the exact Host session that produced an active request context. */
  override async revalidate(context: AuthenticatedPrincipalContext): Promise<void> {
    const sessionId = context.sessionId
    if (sessionId === undefined || !isOpaqueId(sessionId)) throw unauthenticated()
    const session = this.sessions.get(sessionId)
    if (session === undefined || session.context !== context) throw unauthenticated()
    try {
      assertPrincipalContextActive(context)
    } catch (error) {
      this.revokeSession(sessionId, 'OIDC session expired')
      throw error
    }
    await this.revalidateSession(sessionId, session, true)
  }

  /**
   * Consume a one-time authorization response and establish an opaque session cookie.
   * @param request - exact Host callback request.
   * @param response - response that receives the opaque session or safe failure.
   */
  async handleCallback(request: PrincipalRequest, response: OidcResponse): Promise<void> {
    const clearTransaction = clearCookie(
      TRANSACTION_COOKIE,
      this.options.callbackPath,
      this.options.secureCookies,
    )
    let transaction: LoginTransaction | undefined
    let establishedSessionId: string | undefined
    try {
      const callbackUrl = this.exactCallbackUrl(request)
      if (request.method !== undefined && request.method !== 'GET') throw new Error('callback method rejected')
      const transactionId = cookieValue(request.headers, TRANSACTION_COOKIE)
      if (transactionId === undefined || !isOpaqueId(transactionId)) throw new Error('login transaction missing')
      transaction = this.transactions.get(transactionId)
      this.transactions.delete(transactionId)
      if (transaction === undefined || transaction.expiresAt <= Date.now()) throw new Error('login transaction expired')
      if (callbackUrl.searchParams.get('state') !== transaction.state) throw new Error('OIDC state mismatch')
      if (callbackUrl.searchParams.has('error')) throw new Error('OIDC authorization rejected')

      const tokens = await authorizationCodeGrant(this.oidc, callbackUrl, {
        pkceCodeVerifier: transaction.codeVerifier,
        expectedState: transaction.state,
        expectedNonce: transaction.nonce,
        idTokenExpected: true,
      })
      const claims = tokens.claims()
      validateIdTokenClaims(claims, transaction.nonce, this.options)
      this.assertLoginNotLoggedOut(claims)
      const accessToken = tokens.access_token
      const introspection = await this.introspect(accessToken)
      validateIntrospection(introspection, claims.sub, this.options)
      this.assertLoginNotLoggedOut(claims)

      const now = Date.now()
      const expiresAt = sessionExpiration(now, tokens.expiresIn(), claims.exp, introspection.exp, this.options)
      const controller = new AbortController()
      const sessionId = opaqueId()
      const sid = cleanClaim(claims.sid)
      const context: AuthenticatedPrincipalContext = Object.freeze({
        principal: safePrincipal(claims, this.options.issuer, now),
        expiresAt,
        invalidated: controller.signal,
        revalidateIntervalMs: Math.max(MIN_STREAM_REVALIDATE_INTERVAL_MS, this.options.revalidateIntervalMs),
        sessionId,
      })
      this.makeRoom(this.sessions, this.options.maxSessions, (id) => {
        this.revokeSession(id, 'OIDC session capacity')
      })
      this.sessions.set(sessionId, {
        context,
        controller,
        accessToken,
        subject: claims.sub,
        ...(sid === undefined ? {} : { sid }),
        lastValidatedAt: now,
      })
      establishedSessionId = sessionId
      response.setHeader?.('set-cookie', [
        clearTransaction,
        serializeCookie(
          SESSION_COOKIE,
          sessionId,
          expiresAt - now,
          '/',
          this.options.secureCookies,
        ),
      ])
      response.writeHead(303, {
        'cache-control': 'no-store',
        location: transaction.returnTo,
      })
      response.end()
    } catch (error) {
      if (establishedSessionId !== undefined) {
        this.revokeSession(establishedSessionId, 'OIDC callback response failed')
      }
      response.setHeader?.('set-cookie', [
        clearTransaction,
        clearCookie(SESSION_COOKIE, '/', this.options.secureCookies),
      ])
      const status = isProviderFailure(error) ? 503 : 401
      response.writeHead(status, {
        'cache-control': 'no-store',
        'content-type': 'text/plain; charset=utf-8',
      })
      response.end(status === 503 ? 'identity provider unavailable' : 'unauthorized')
    }
  }

  /**
   * Revoke the local opaque session and redirect to the configured IdP logout endpoint.
   * @param request - Host logout request carrying an optional opaque session.
   * @param response - response that clears the session cookie and redirects.
   */
  handleLogout(request: PrincipalRequest, response: OidcResponse): void {
    if (request.method !== 'POST') {
      response.writeHead(405, { allow: 'POST', 'cache-control': 'no-store' })
      response.end()
      return
    }
    if (headerValue(request.headers, 'origin') !== this.options.redirectUri.origin) {
      response.writeHead(403, { 'cache-control': 'no-store' })
      response.end()
      return
    }
    try {
      this.assertApplicationAuthority(request)
      const sessionId = cookieValue(request.headers, SESSION_COOKIE)
      if (sessionId !== undefined && isOpaqueId(sessionId)) this.revokeSession(sessionId, 'OIDC front-channel logout')
      response.setHeader?.('set-cookie', clearCookie(SESSION_COOKIE, '/', this.options.secureCookies))
      const metadata = this.oidc.serverMetadata()
      const location = metadata.end_session_endpoint === undefined
        ? this.options.postLogoutRedirectUri
        : buildEndSessionUrl(this.oidc, {
          post_logout_redirect_uri: this.options.postLogoutRedirectUri.href,
        })
      response.writeHead(303, { 'cache-control': 'no-store', location: location.href })
      response.end()
    } catch {
      writeUnavailable(response)
    }
  }

  /**
   * Validate one signed back-channel logout token and invalidate its target session(s).
   * @param logoutToken - compact signed logout JWT supplied by the configured issuer.
   */
  async processBackchannelLogout(logoutToken: string): Promise<void> {
    if (typeof logoutToken !== 'string' || logoutToken.length === 0 || logoutToken.length > MAX_BACKCHANNEL_BODY_BYTES) {
      throw new Error('invalid logout token')
    }
    let verification: Awaited<ReturnType<typeof jwtVerify<BackchannelLogoutClaims>>>
    try {
      verification = await jwtVerify<BackchannelLogoutClaims>(logoutToken, this.logoutKeys, {
        issuer: this.options.issuer,
        audience: this.options.clientId,
        algorithms: [this.options.signingAlgorithm],
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
        maxTokenAge: BACKCHANNEL_MAX_AGE_SECONDS,
      })
    } catch (cause) {
      if (!isJwksProviderFailure(cause)) throw cause
      throw new PrincipalAuthenticationError(
        'principal-unavailable',
        503,
        'identity provider unavailable',
        { cause },
      )
    }
    const { payload, protectedHeader } = verification
    if (protectedHeader.alg !== this.options.signingAlgorithm) throw new Error('unexpected logout token algorithm')
    if (protectedHeader.typ !== undefined && protectedHeader.typ.toLowerCase() !== 'logout+jwt') {
      throw new Error('unexpected logout token type')
    }
    if (typeof payload.iat !== 'number' || typeof payload.jti !== 'string' || payload.jti === '') {
      throw new Error('logout token is missing required claims')
    }
    if (payload.nonce !== undefined) throw new Error('logout token must not contain nonce')
    if (!isLogoutEvent(payload.events)) throw new Error('logout token event is invalid')
    const sid = cleanClaim(payload.sid)
    const subject = cleanClaim(payload.sub)
    let logoutTarget: string
    if (sid !== undefined) logoutTarget = logoutTargetKey('sid', sid)
    else if (subject !== undefined) logoutTarget = logoutTargetKey('sub', subject)
    else throw new Error('logout token has no session target')
    const tokenId = logoutTokenId(payload.jti)
    this.recordBackchannelLogout(tokenId, logoutTarget, payload.iat)

    for (const [sessionId, session] of [...this.sessions]) {
      const matches = sid === undefined ? session.subject === subject : session.sid === sid
      if (matches) this.revokeSession(sessionId, 'OIDC back-channel logout')
    }
  }

  /**
   * HTTP form adapter for the OIDC back-channel logout route.
   * @param request - form-encoded Host request from the configured issuer.
   * @param response - minimal success or safe failure response.
   */
  async handleBackchannelLogout(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (request.method !== 'POST') {
      response.writeHead(405, { allow: 'POST', 'cache-control': 'no-store' })
      response.end()
      return
    }
    const contentType = headerValue(request.headers, 'content-type')?.split(';', 1)[0]?.trim().toLowerCase()
    if (contentType !== 'application/x-www-form-urlencoded') {
      response.writeHead(415, { 'cache-control': 'no-store' })
      response.end()
      return
    }
    try {
      const body = await readBody(request, MAX_BACKCHANNEL_BODY_BYTES)
      const form = new URLSearchParams(body)
      const values = form.getAll('logout_token')
      const logoutToken = values[0]
      if (values.length !== 1 || logoutToken === undefined) throw new Error('logout token form is invalid')
      await this.processBackchannelLogout(logoutToken)
      response.writeHead(200, { 'cache-control': 'no-store' })
      response.end()
    } catch (error) {
      response.writeHead(isProviderFailure(error) ? 503 : 400, { 'cache-control': 'no-store' })
      response.end()
    }
  }

  private async revalidateSession(sessionId: string, session: SessionRecord, force: boolean): Promise<void> {
    assertPrincipalContextActive(session.context)
    if (!force && Date.now() - session.lastValidatedAt < this.options.revalidateIntervalMs) return
    if (session.revalidating !== undefined) return session.revalidating
    const pending = this.performRevalidation(sessionId, session).finally(() => {
      if (session.revalidating === pending) delete session.revalidating
    })
    session.revalidating = pending
    return pending
  }

  private async performRevalidation(sessionId: string, session: SessionRecord): Promise<void> {
    let introspection: IntrospectionResponse
    try {
      introspection = await this.introspect(session.accessToken)
    } catch (cause) {
      this.revokeSession(sessionId, 'OIDC introspection unavailable')
      throw new PrincipalAuthenticationError(
        'principal-unavailable',
        503,
        'identity provider unavailable',
        { cause },
      )
    }
    try {
      validateIntrospection(introspection, session.subject, this.options)
    } catch (cause) {
      this.revokeSession(sessionId, 'OIDC token inactive')
      throw new PrincipalAuthenticationError(
        'principal-unauthenticated',
        401,
        'authenticated Principal is no longer active',
        { cause },
      )
    }
    session.lastValidatedAt = Date.now()
  }

  private introspect(accessToken: string): Promise<IntrospectionResponse> {
    return tokenIntrospection(this.oidc, accessToken, { token_type_hint: 'access_token' })
  }

  private revokeSession(sessionId: string, reason: string): void {
    const session = this.sessions.get(sessionId)
    if (session === undefined) return
    this.sessions.delete(sessionId)
    if (!session.controller.signal.aborted) session.controller.abort(new Error(reason))
  }

  private applicationUrl(request: PrincipalRequest): URL {
    const url = requestUrl(request, this.options.redirectUri)
    if (url.origin !== this.options.redirectUri.origin) throw new Error('request authority rejected')
    return url
  }

  private assertApplicationAuthority(request: PrincipalRequest): void {
    this.applicationUrl(request)
  }

  private exactCallbackUrl(request: PrincipalRequest): URL {
    const url = this.applicationUrl(request)
    if (url.pathname !== this.options.callbackPath || url.hash !== '') throw new Error('callback URI mismatch')
    return url
  }

  private cleanupTransactions(): void {
    const now = Date.now()
    for (const [id, transaction] of this.transactions) {
      if (transaction.expiresAt <= now) this.transactions.delete(id)
    }
  }

  private cleanupLogoutTokenIds(now = Date.now()): void {
    for (const [id, expiresAt] of this.logoutTokenIds) {
      if (expiresAt <= now) this.logoutTokenIds.delete(id)
    }
  }

  private assertLoginNotLoggedOut(claims: IDToken): void {
    this.cleanupLogoutTargets()
    const sid = cleanClaim(claims.sid)
    const tombstones = [
      this.logoutTargets.get(logoutTargetKey('sub', claims.sub)),
      ...(sid === undefined ? [] : [this.logoutTargets.get(logoutTargetKey('sid', sid))]),
    ]
    if (tombstones.some(tombstone => tombstone !== undefined && claims.iat <= tombstone.issuedAt)) {
      throw new Error('OIDC login session was already logged out')
    }
  }

  private recordBackchannelLogout(tokenId: string, key: string, issuedAt: number): void {
    const now = Date.now()
    this.cleanupLogoutTokenIds(now)
    this.cleanupLogoutTargets(now)
    if (this.logoutTokenIds.has(tokenId)) throw new Error('logout token replayed')

    const previous = this.logoutTargets.get(key)
    const tokenCapacity = Math.min(MAX_LOGOUT_TOKEN_IDS, Math.max(2, this.options.maxSessions * 2))
    const targetCapacity = Math.min(MAX_LOGOUT_TARGET_TOMBSTONES, Math.max(2, this.options.maxSessions * 2))
    if (this.logoutTokenIds.size >= tokenCapacity
      || (previous === undefined && this.logoutTargets.size >= targetCapacity)) {
      throw new PrincipalAuthenticationError(
        'principal-unavailable',
        503,
        'back-channel logout capacity unavailable',
      )
    }

    const tokenExpiresAt = backchannelReplayExpiresAt(issuedAt, now)
    this.logoutTokenIds.set(tokenId, tokenExpiresAt)
    this.logoutTargets.set(key, {
      issuedAt: Math.max(issuedAt, previous?.issuedAt ?? issuedAt),
      expiresAt: Math.max(tokenExpiresAt + this.options.transactionTtlMs, previous?.expiresAt ?? 0),
    })
  }

  private cleanupLogoutTargets(now = Date.now()): void {
    for (const [key, tombstone] of this.logoutTargets) {
      if (tombstone.expiresAt <= now) this.logoutTargets.delete(key)
    }
  }

  private makeRoom<T>(map: Map<string, T>, maximum: number, remove?: (id: string) => void): void {
    while (map.size >= maximum) {
      const oldest = map.keys().next().value
      if (oldest === undefined) return
      if (remove === undefined) map.delete(oldest)
      else remove(oldest)
    }
  }
}

/** Discover the issuer, install the provider, and claim its exact browser routes. */
export async function apply(ctx: Context, config: Config): Promise<void> {
  const provider = await OidcPrincipalProvider.create(ctx, config)
  const callbackPath = new URL(config.redirectUri).pathname
  const logoutPath = config.logoutPath ?? DEFAULT_LOGOUT_PATH
  const backchannelLogoutPath = config.backchannelLogoutPath ?? DEFAULT_BACKCHANNEL_LOGOUT_PATH
  ctx.effect(() => {
    const disposers: (() => void)[] = []
    try {
      disposers.push(ctx.webServer.register({
        kind: 'exact',
        path: callbackPath,
        handler: (request, response) => provider.handleCallback(request, response),
      }))
      disposers.push(ctx.webServer.register({
        kind: 'exact',
        path: logoutPath,
        handler: (request, response) => { provider.handleLogout(request, response) },
      }))
      disposers.push(ctx.webServer.register({
        kind: 'exact',
        path: backchannelLogoutPath,
        handler: (request, response) => provider.handleBackchannelLogout(request, response),
      }))
    } catch (error) {
      for (const dispose of disposers.reverse()) dispose()
      throw error
    }
    return () => { for (const dispose of disposers.reverse()) dispose() }
  }, 'principal-oidc: callback and logout routes')
}

function resolveConfig(input: Config): ResolvedConfig {
  const issuerUrl = exactAbsoluteUrl(input.issuer, 'issuer')
  if (issuerUrl.search !== '' || issuerUrl.hash !== '') throw new TypeError('OIDC issuer must not contain query or fragment')
  const redirectUri = exactAbsoluteUrl(input.redirectUri, 'redirectUri')
  if (redirectUri.search !== '' || redirectUri.hash !== '') {
    throw new TypeError('OIDC redirectUri must not contain query or fragment')
  }
  const postLogoutRedirectUri = exactAbsoluteUrl(
    input.postLogoutRedirectUri ?? `${redirectUri.origin}/`,
    'postLogoutRedirectUri',
  )
  if (postLogoutRedirectUri.origin !== redirectUri.origin || postLogoutRedirectUri.hash !== '') {
    throw new TypeError('OIDC postLogoutRedirectUri must use the application origin and have no fragment')
  }
  const allowInsecureHttp = input.allowInsecureHttp ?? false
  for (const url of [issuerUrl, redirectUri, postLogoutRedirectUri]) {
    if (url.protocol === 'https:') continue
    if (!allowInsecureHttp || url.protocol !== 'http:' || !isLoopback(url.hostname)) {
      throw new TypeError('OIDC URLs must use HTTPS; HTTP requires explicit loopback development mode')
    }
  }
  requireNonEmpty(input.clientId, 'clientId')
  requireNonEmpty(input.accessTokenAudience, 'accessTokenAudience')
  if (input.clientSecret !== undefined) requireNonEmpty(input.clientSecret, 'clientSecret')
  const scopes = input.scopes ?? ['openid', 'profile', 'email']
  if (scopes.length === 0 || !scopes.includes('openid')) throw new TypeError('OIDC scopes must include openid')
  const uniqueScopes = [...new Set(scopes.map((scope) => {
    requireNonEmpty(scope, 'scope')
    if (/\s/u.test(scope)) throw new TypeError('OIDC scopes must not contain whitespace')
    return scope
  }))]
  const signingAlgorithm = input.signingAlgorithm ?? 'RS256'
  if (!/^(?:RS|PS|ES)(?:256|384|512)$|^EdDSA$/u.test(signingAlgorithm)) {
    throw new TypeError('OIDC signingAlgorithm must be an approved asymmetric JWS algorithm')
  }
  const callbackPath = exactRoutePath(redirectUri.pathname, 'redirectUri pathname')
  const logoutPath = exactRoutePath(input.logoutPath ?? DEFAULT_LOGOUT_PATH, 'logoutPath')
  const backchannelLogoutPath = exactRoutePath(
    input.backchannelLogoutPath ?? DEFAULT_BACKCHANNEL_LOGOUT_PATH,
    'backchannelLogoutPath',
  )
  if (new Set([callbackPath, logoutPath, backchannelLogoutPath]).size !== 3) {
    throw new TypeError('OIDC callback and logout routes must be distinct')
  }
  return {
    issuer: input.issuer,
    issuerUrl,
    clientId: input.clientId,
    accessTokenAudience: input.accessTokenAudience,
    ...(input.clientSecret === undefined ? {} : { clientSecret: input.clientSecret }),
    redirectUri,
    postLogoutRedirectUri,
    scopes: uniqueScopes,
    signingAlgorithm,
    revalidateIntervalMs: boundedNonNegativeInteger(
      input.revalidateIntervalSeconds ?? 15,
      'revalidateIntervalSeconds',
      MAX_REVALIDATE_INTERVAL_SECONDS,
    ) * 1_000,
    sessionMaxAgeMs: positiveInteger(input.sessionMaxAgeSeconds ?? 8 * 60 * 60, 'sessionMaxAgeSeconds') * 1_000,
    transactionTtlMs: positiveInteger(input.transactionTtlSeconds ?? 5 * 60, 'transactionTtlSeconds') * 1_000,
    maxSessions: positiveInteger(input.maxSessions ?? 10_000, 'maxSessions'),
    maxTransactions: positiveInteger(input.maxTransactions ?? 1_024, 'maxTransactions'),
    callbackPath,
    logoutPath,
    backchannelLogoutPath,
    secureCookies: redirectUri.protocol === 'https:',
    allowInsecureHttp,
  }
}

function validateIdTokenClaims(
  claims: IDToken | undefined,
  nonce: string,
  options: ResolvedConfig,
): asserts claims is IDToken {
  if (claims === undefined) throw new Error('OIDC ID Token is missing')
  if (claims.iss !== options.issuer || !audienceIncludes(claims.aud, options.clientId)) {
    throw new Error('OIDC ID Token authority mismatch')
  }
  if (claims.nonce !== nonce) throw new Error('OIDC nonce mismatch')
  requireNonEmpty(claims.sub, 'subject')
  if (!Number.isFinite(claims.exp) || claims.exp * 1_000 <= Date.now()) throw new Error('OIDC ID Token expired')
}

function validateIntrospection(
  introspection: IntrospectionResponse,
  subject: string,
  options: ResolvedConfig,
): void {
  if (!introspection.active) throw new Error('OIDC access token is inactive')
  if (introspection.iss !== options.issuer) {
    throw new Error('OIDC introspection issuer mismatch')
  }
  if (introspection.aud === undefined || !audienceIncludes(introspection.aud, options.accessTokenAudience)) {
    throw new Error('OIDC introspection audience mismatch')
  }
  if (introspection.client_id !== options.clientId) {
    throw new Error('OIDC introspection client mismatch')
  }
  if (introspection.sub !== subject) {
    throw new Error('OIDC introspection subject mismatch')
  }
  if (typeof introspection.exp !== 'number'
    || !Number.isFinite(introspection.exp)
    || introspection.exp * 1_000 <= Date.now()) {
    throw new Error('OIDC access token expired')
  }
}

function safePrincipal(claims: IDToken, issuer: string, now: number) {
  const name = cleanClaim(claims.name) ?? cleanClaim(claims.preferred_username)
  const email = claims.email_verified === true ? cleanClaim(claims.email) : undefined
  const authTime = typeof claims.auth_time === 'number'
    && Number.isFinite(claims.auth_time)
    && claims.auth_time * 1_000 <= now + CLOCK_TOLERANCE_SECONDS * 1_000
    ? new Date(claims.auth_time * 1_000).toISOString()
    : new Date(now).toISOString()
  return verifiedPrincipal({
    issuer,
    subject: claims.sub,
    ...(name === undefined ? {} : { displayName: name }),
    ...(email === undefined ? {} : { email }),
    authenticatedAt: authTime,
  })
}

function sessionExpiration(
  now: number,
  expiresIn: number | undefined,
  idTokenExp: number,
  introspectionExp: number | undefined,
  options: ResolvedConfig,
): number {
  const candidates = [now + options.sessionMaxAgeMs, idTokenExp * 1_000]
  if (expiresIn !== undefined) candidates.push(now + expiresIn * 1_000)
  if (introspectionExp !== undefined) candidates.push(introspectionExp * 1_000)
  const expiresAt = Math.min(...candidates)
  if (!Number.isFinite(expiresAt) || expiresAt <= now) throw new Error('OIDC token lifetime is invalid')
  return expiresAt
}

function requireMetadataUrl(value: string | undefined, label: string, options: ResolvedConfig): URL {
  if (value === undefined) throw new Error(`OIDC discovery is missing ${label}`)
  const url = exactAbsoluteUrl(value, label)
  if (url.protocol !== 'https:' && !(options.allowInsecureHttp && url.protocol === 'http:' && isLoopback(url.hostname))) {
    throw new Error(`OIDC ${label} must use HTTPS`)
  }
  return url
}

function exactAbsoluteUrl(value: string, label: string): URL {
  requireNonEmpty(value, label)
  let url: URL
  try {
    url = new URL(value)
  } catch (cause) {
    throw new TypeError(`OIDC ${label} must be an absolute URL`, { cause })
  }
  const exact = url.href === value || (url.pathname === '/' && url.search === '' && url.hash === '' && url.origin === value)
  if (url.username !== '' || url.password !== '' || !exact) {
    throw new TypeError(`OIDC ${label} must be an exact canonical URL without credentials`)
  }
  return url
}

function exactRoutePath(value: string, label: string): string {
  if (!value.startsWith('/') || value === '/' || value.endsWith('/') || value.includes('?') || value.includes('#')) {
    throw new TypeError(`OIDC ${label} must be an absolute non-root path without query, fragment, or trailing slash`)
  }
  return value
}

function requestUrl(request: PrincipalRequest, application: URL): URL {
  const raw = request.url ?? '/'
  let url: URL
  try {
    url = new URL(raw, application.origin)
  } catch (cause) {
    throw new TypeError('OIDC request URL is invalid', { cause })
  }
  const host = headerValue(request.headers, 'host')
  if (host === undefined || host !== application.host) throw new Error('OIDC request Host is not the configured application')
  return url
}

function safeReturnTo(url: URL, options: ResolvedConfig): string {
  if (url.origin !== options.redirectUri.origin || url.pathname === options.callbackPath) return '/'
  return `${url.pathname}${url.search}`
}

function headerValue(
  headers: PrincipalRequest['headers'],
  name: string,
): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  const wanted = name.toLowerCase()
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted || value === undefined) continue
    return Array.isArray(value) ? value.join(wanted === 'cookie' ? '; ' : ', ') : value as string
  }
  return undefined
}

function cookieValue(headers: PrincipalRequest['headers'], name: string): string | undefined {
  const cookie = headerValue(headers, 'cookie')
  if (cookie === undefined) return undefined
  let found: string | undefined
  for (const part of cookie.split(';')) {
    const index = part.indexOf('=')
    if (index < 0 || part.slice(0, index).trim() !== name) continue
    if (found !== undefined) return undefined
    found = part.slice(index + 1).trim()
  }
  return found
}

function serializeCookie(name: string, value: string, lifetimeMs: number, path: string, secure: boolean): string {
  const maxAge = Math.max(1, Math.floor(lifetimeMs / 1_000))
  return `${name}=${value}; Path=${path}; Max-Age=${String(maxAge)}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`
}

function clearCookie(name: string, path: string, secure: boolean): string {
  return `${name}=; Path=${path}; Max-Age=0; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`
}

function opaqueId(): string {
  return randomBytes(32).toString('base64url')
}

function isOpaqueId(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/u.test(value)
}

function audienceIncludes(audience: string | readonly string[], expected: string): boolean {
  return typeof audience === 'string' ? audience === expected : audience.includes(expected)
}

function cleanClaim(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  return trimmed === '' || trimmed.includes('\0') ? undefined : trimmed
}

function isLogoutEvent(events: unknown): boolean {
  if (typeof events !== 'object' || events === null || Array.isArray(events)) return false
  const event = (events as Record<string, unknown>)[BACKCHANNEL_LOGOUT_EVENT]
  return typeof event === 'object' && event !== null && !Array.isArray(event)
    && Object.keys(event).length === 0
}

function logoutTargetKey(kind: 'sid' | 'sub', value: string): string {
  return `${kind}\0${value}`
}

function logoutTokenId(jti: string): string {
  return createHash('sha256').update(jti).digest('base64url')
}

function backchannelReplayExpiresAt(issuedAt: number, processedAt: number): number {
  const retentionMs = BACKCHANNEL_REPLAY_RETENTION_SECONDS * 1_000
  return Math.max((issuedAt + BACKCHANNEL_REPLAY_RETENTION_SECONDS) * 1_000, processedAt + retentionMs)
}

function requireNonEmpty(value: string, label: string): void {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0')) {
    throw new TypeError(`OIDC ${label} must be a non-empty string without NUL`)
  }
}

function positiveInteger(value: number, label: string, allowZero = false): number {
  if (!Number.isSafeInteger(value) || (allowZero ? value < 0 : value <= 0)) {
    throw new TypeError(`OIDC ${label} must be ${allowZero ? 'a non-negative' : 'a positive'} integer`)
  }
  return value
}

function boundedNonNegativeInteger(value: number, label: string, maximum: number): number {
  const resolved = positiveInteger(value, label, true)
  if (resolved > maximum) throw new TypeError(`OIDC ${label} must not exceed ${String(maximum)}`)
  return resolved
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'
}

function unauthenticated(): PrincipalAuthenticationError {
  return new PrincipalAuthenticationError('principal-unauthenticated', 401, 'authenticated Principal is required')
}

function writeUnavailable(response: PrincipalResponse): void {
  response.writeHead(503, {
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
  })
  response.end('identity provider unavailable')
}

function isProviderFailure(error: unknown): boolean {
  if (error instanceof PrincipalAuthenticationError) return error.status === 503
  if (error instanceof TypeError) {
    return error.message === 'fetch failed' || isNetworkCause(error.cause)
  }
  if (error instanceof ResponseBodyError) {
    return error.status === 408
      || error.status === 429
      || error.status >= 500
      || error.error === 'invalid_client'
      || error.error === 'unauthorized_client'
      || error.error === 'server_error'
      || error.error === 'temporarily_unavailable'
  }
  if (error instanceof ClientError) {
    return error.code === 'OAUTH_TIMEOUT'
      || error.code === 'OAUTH_ABORT'
      || error.code === RESPONSE_IS_NOT_CONFORM
      || error.code === RESPONSE_IS_NOT_JSON
      || error.code === HTTP_REQUEST_FORBIDDEN
      || error.code === REQUEST_PROTOCOL_FORBIDDEN
      || isProviderFailure(error.cause)
  }
  if (error instanceof joseErrors.JWKSTimeout || error instanceof joseErrors.JWKSInvalid) return true
  return error instanceof Error && error.cause !== undefined && isProviderFailure(error.cause)
}

function isJwksProviderFailure(error: unknown): boolean {
  if (error instanceof joseErrors.JWKSTimeout || error instanceof joseErrors.JWKSInvalid) return true
  if (error instanceof joseErrors.JOSEError) return error.code === 'ERR_JOSE_GENERIC'
  return error instanceof TypeError && (error.message === 'fetch failed' || isNetworkCause(error.cause))
}

function isNetworkCause(cause: unknown): boolean {
  if (!(cause instanceof Error)) return false
  const code = (cause as NodeJS.ErrnoException).code
  return typeof code === 'string' && (
    code.startsWith('ECONN')
    || code.startsWith('EHOST')
    || code.startsWith('ENET')
    || code === 'ETIMEDOUT'
    || code.startsWith('UND_ERR_')
  )
}

async function readBody(request: IncomingMessage, maximum: number): Promise<string> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array)
    total += bytes.length
    if (total > maximum) throw new Error('back-channel logout body is too large')
    chunks.push(bytes)
  }
  return Buffer.concat(chunks).toString('utf8')
}
