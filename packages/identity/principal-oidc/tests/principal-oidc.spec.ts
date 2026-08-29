import { createHash } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { Readable } from 'node:stream'
import { Context } from '@deepseek-ai/cordis'
import { PrincipalAuthenticationError } from '@deepseek-ai/dsh-principal'
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from 'jose'
import { calculatePKCECodeChallenge, customFetch, type Configuration } from 'openid-client'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { OidcPrincipalProvider, type Config } from '../src/index.ts'

const APP_ORIGIN = 'http://127.0.0.1:47891'
const APP_HOST = '127.0.0.1:47891'
const CALLBACK_PATH = '/.dsh/oidc/callback'
const CALLBACK_URI = `${APP_ORIGIN}${CALLBACK_PATH}`

type TokenMode =
  | 'valid'
  | 'pkce'
  | 'nonce'
  | 'issuer'
  | 'audience'
  | 'expired'
  | 'signature'
  | 'token-outage'
  | 'token-rate-limit'
  | 'token-server-error'
  | 'token-transient'
  | 'introspection-missing'
  | 'introspection-issuer'
  | 'introspection-audience'
  | 'introspection-client'
  | 'introspection-subject'
  | 'introspection-expired'

class TestResponse {
  status = 0
  readonly headers: Record<string, string | readonly string[]> = {}
  body = ''

  setHeader(name: string, value: string | readonly string[]): this {
    this.headers[name.toLowerCase()] = value
    return this
  }

  writeHead(status: number, headers: Readonly<Record<string, string>> = {}): this {
    this.status = status
    for (const [name, value] of Object.entries(headers)) this.headers[name.toLowerCase()] = value
    return this
  }

  end(body = ''): this {
    this.body = body
    return this
  }

  header(name: string): string | readonly string[] | undefined {
    return this.headers[name.toLowerCase()]
  }
}

class FailFirstEndResponse extends TestResponse {
  readonly setCookieHistory: (string | readonly string[])[] = []
  private fail = true

  override setHeader(name: string, value: string | readonly string[]): this {
    if (name.toLowerCase() === 'set-cookie') this.setCookieHistory.push(value)
    return super.setHeader(name, value)
  }

  override end(body = ''): this {
    if (this.fail) {
      this.fail = false
      throw new Error('fixture callback response failure')
    }
    return super.end(body)
  }
}

class MockIssuer {
  readonly server: Server
  issuer = ''
  mode: TokenMode = 'valid'
  introspectionActive = true
  introspectionOutage = false
  jwksOutage = false
  discoveryIssuerOverride: string | undefined
  expectedChallenge = ''
  expectedNonce = ''
  pkceVerified = false
  introspectionCount = 0
  private privateKey!: CryptoKey
  private invalidPrivateKey!: CryptoKey
  private jwk!: Record<string, unknown>
  private accessCounter = 0
  private introspectionPause: {
    readonly entered: () => void
    readonly released: Promise<void>
  } | undefined

  constructor() {
    this.server = createServer((request, response) => {
      void this.route(request, response).catch(() => {
        if (!response.headersSent) response.writeHead(500, { 'content-type': 'application/json' })
        response.end('{"error":"server_error"}')
      })
    })
  }

  async start(): Promise<void> {
    const pair = await generateKeyPair('RS256')
    const invalidPair = await generateKeyPair('RS256')
    this.privateKey = pair.privateKey
    this.invalidPrivateKey = invalidPair.privateKey
    this.jwk = { ...await exportJWK(pair.publicKey), kid: 'primary', alg: 'RS256', use: 'sig' }
    await new Promise<void>((resolve, reject) => {
      this.server.once('error', reject)
      this.server.listen(0, '127.0.0.1', () => {
        this.server.off('error', reject)
        resolve()
      })
    })
    const address = this.server.address()
    if (address === null || typeof address === 'string') throw new Error('mock issuer did not bind TCP')
    this.issuer = `http://127.0.0.1:${String(address.port)}/realms/test`
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => { if (error === undefined) resolve(); else reject(error) })
    })
  }

  rememberAuthorization(location: URL): void {
    this.expectedChallenge = location.searchParams.get('code_challenge') ?? ''
    this.expectedNonce = location.searchParams.get('nonce') ?? ''
    this.pkceVerified = false
  }

  pauseNextIntrospection(): { readonly entered: Promise<void>; release(): void } {
    if (this.introspectionPause !== undefined) throw new Error('introspection is already paused')
    const entered = Promise.withResolvers<undefined>()
    const released = Promise.withResolvers<undefined>()
    this.introspectionPause = {
      entered: () => { entered.resolve(undefined) },
      released: released.promise,
    }
    return { entered: entered.promise, release: () => { released.resolve(undefined) } }
  }

  async logoutToken(input: {
    sid?: string
    sub?: string
    audience?: string
    jti: string
    issuedAt?: number
  }): Promise<string> {
    return new SignJWT({
      ...(input.sid === undefined ? {} : { sid: input.sid }),
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'primary', typ: 'logout+jwt' })
      .setIssuer(this.issuer)
      .setAudience(input.audience ?? 'dsh-browser')
      .setIssuedAt(input.issuedAt)
      .setJti(input.jti)
      .setSubject(input.sub ?? 'alice')
      .sign(this.privateKey)
  }

  private async route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? '/', this.issuer)
    if (url.pathname === '/realms/test/.well-known/openid-configuration') {
      json(response, 200, {
        issuer: this.discoveryIssuerOverride ?? this.issuer,
        authorization_endpoint: `${this.issuer}/authorize`,
        token_endpoint: `${this.issuer}/token`,
        introspection_endpoint: `${this.issuer}/introspect`,
        jwks_uri: `${this.issuer}/jwks`,
        end_session_endpoint: `${this.issuer}/logout`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
        code_challenge_methods_supported: ['S256'],
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
      })
      return
    }
    if (url.pathname === '/realms/test/jwks') {
      if (this.jwksOutage) {
        json(response, 503, { error: 'temporarily_unavailable' })
        return
      }
      json(response, 200, { keys: [this.jwk] })
      return
    }
    if (url.pathname === '/realms/test/token') {
      if (this.mode === 'token-outage') {
        json(response, 503, { error: 'temporarily_unavailable' })
        return
      }
      if (this.mode === 'token-rate-limit') {
        json(response, 429, { error: 'rate_limited' })
        return
      }
      if (this.mode === 'token-server-error') {
        json(response, 400, { error: 'server_error' })
        return
      }
      if (this.mode === 'token-transient') {
        json(response, 400, { error: 'temporarily_unavailable' })
        return
      }
      const form = new URLSearchParams(await requestBody(request))
      const verifier = form.get('code_verifier') ?? ''
      this.pkceVerified = await calculatePKCECodeChallenge(verifier) === this.expectedChallenge
      if (this.mode === 'pkce' || !this.pkceVerified || form.get('redirect_uri') !== CALLBACK_URI) {
        json(response, 400, { error: 'invalid_grant' })
        return
      }
      if (form.get('client_id') !== 'dsh-browser' || form.get('client_secret') !== 'test-secret') {
        json(response, 401, { error: 'invalid_client' })
        return
      }
      const now = Math.floor(Date.now() / 1_000)
      const token = new SignJWT({
        nonce: this.mode === 'nonce' ? 'wrong-nonce' : this.expectedNonce,
        sid: 'sid-1',
        name: 'Alice Example',
        preferred_username: 'alice',
        email: 'alice@example.test',
        email_verified: true,
        private_role: 'must-not-escape',
      })
        .setProtectedHeader({ alg: 'RS256', kid: this.mode === 'signature' ? 'unknown' : 'primary' })
        .setIssuer(this.mode === 'issuer' ? `${this.issuer}/wrong` : this.issuer)
        .setSubject('alice')
        .setAudience(this.mode === 'audience' ? 'another-client' : 'dsh-browser')
        .setIssuedAt(now)
        .setExpirationTime(this.mode === 'expired' ? now - 120 : now + 600)
      const idToken = await token.sign(this.mode === 'signature' ? this.invalidPrivateKey : this.privateKey)
      this.accessCounter += 1
      json(response, 200, {
        access_token: `opaque-access-${String(this.accessCounter)}`,
        token_type: 'Bearer',
        expires_in: 600,
        id_token: idToken,
      })
      return
    }
    if (url.pathname === '/realms/test/introspect') {
      this.introspectionCount += 1
      const pause = this.introspectionPause
      if (pause !== undefined) {
        this.introspectionPause = undefined
        pause.entered()
        await pause.released
      }
      if (this.introspectionOutage) {
        json(response, 503, { error: 'temporarily_unavailable' })
        return
      }
      const form = new URLSearchParams(await requestBody(request))
      if (form.get('client_id') !== 'dsh-browser' || form.get('client_secret') !== 'test-secret') {
        json(response, 401, { error: 'invalid_client' })
        return
      }
      if (!this.introspectionActive) {
        json(response, 200, { active: false })
        return
      }
      if (this.mode === 'introspection-missing') {
        json(response, 200, { active: true })
        return
      }
      json(response, 200, {
        active: true,
        iss: this.mode === 'introspection-issuer' ? `${this.issuer}/wrong` : this.issuer,
        aud: this.mode === 'introspection-audience' ? ['another-api'] : ['dsh-api'],
        client_id: this.mode === 'introspection-client' ? 'another-client' : 'dsh-browser',
        sub: this.mode === 'introspection-subject' ? 'mallory' : 'alice',
        sid: 'sid-1',
        exp: Math.floor(Date.now() / 1_000) + (this.mode === 'introspection-expired' ? -120 : 600),
      })
      return
    }
    response.writeHead(404)
    response.end()
  }
}

const issuer = new MockIssuer()

beforeAll(async () => { await issuer.start() })
afterAll(async () => { await issuer.stop() })

function providerConfig(overrides: Partial<Config> = {}): Config {
  return {
    issuer: issuer.issuer,
    clientId: 'dsh-browser',
    accessTokenAudience: 'dsh-api',
    clientSecret: 'test-secret',
    redirectUri: CALLBACK_URI,
    postLogoutRedirectUri: `${APP_ORIGIN}/signed-out`,
    revalidateIntervalSeconds: 0,
    allowInsecureHttp: true,
    ...overrides,
  }
}

async function createProvider(overrides: Partial<Config> = {}): Promise<OidcPrincipalProvider> {
  return OidcPrincipalProvider.create(new Context(), providerConfig(overrides))
}

async function beginLogin(provider: OidcPrincipalProvider, returnTo = '/quotes/current?tab=review') {
  const response = new TestResponse()
  expect(await provider.authorizeIndex({
    method: 'GET',
    url: returnTo,
    headers: { host: APP_HOST },
  }, response)).toBe(false)
  expect(response.status).toBe(302)
  const location = new URL(stringHeader(response, 'location'))
  issuer.rememberAuthorization(location)
  return { response, location, transactionCookie: responseCookie(response, 'dsh_oidc_transaction') }
}

async function completeLogin(
  provider: OidcPrincipalProvider,
  login: Awaited<ReturnType<typeof beginLogin>>,
  state = login.location.searchParams.get('state') ?? '',
): Promise<TestResponse> {
  const response = new TestResponse()
  await provider.handleCallback({
    method: 'GET',
    url: `${CALLBACK_PATH}?code=authorization-code&state=${encodeURIComponent(state)}`,
    headers: { host: APP_HOST, cookie: login.transactionCookie },
  }, response)
  return response
}

async function activeSession(provider: OidcPrincipalProvider) {
  issuer.mode = 'valid'
  issuer.introspectionActive = true
  issuer.introspectionOutage = false
  const callback = await completeLogin(provider, await beginLogin(provider))
  expect(callback.status).toBe(303)
  const cookie = responseCookie(callback, 'dsh_oidc_session')
  const context = await provider.authenticate({ url: '/api', headers: { host: APP_HOST, cookie } })
  return { callback, cookie, context }
}

function logoutTokenIds(provider: OidcPrincipalProvider): Map<string, number> {
  return Reflect.get(provider, 'logoutTokenIds') as Map<string, number>
}

function logoutTargets(provider: OidcPrincipalProvider): Map<string, { readonly issuedAt: number; readonly expiresAt: number }> {
  return Reflect.get(provider, 'logoutTargets') as Map<
    string,
    { readonly issuedAt: number; readonly expiresAt: number }
  >
}

async function postBackchannelLogout(provider: OidcPrincipalProvider, logoutToken: string): Promise<TestResponse> {
  const body = new URLSearchParams({ logout_token: logoutToken }).toString()
  const request = Readable.from([body]) as IncomingMessage
  request.method = 'POST'
  request.headers = { 'content-type': 'application/x-www-form-urlencoded' }
  const response = new TestResponse()
  await provider.handleBackchannelLogout(request, response as unknown as ServerResponse)
  return response
}

describe('OIDC Principal provider', () => {
  it('discovers the issuer and completes Code + PKCE into an opaque safe session', async () => {
    issuer.mode = 'valid'
    issuer.introspectionActive = true
    issuer.introspectionOutage = false
    const provider = await createProvider()
    const login = await beginLogin(provider)
    expect(login.location.origin).toBe(new URL(issuer.issuer).origin)
    expect(login.location.pathname).toBe('/realms/test/authorize')
    expect(login.location.searchParams.get('redirect_uri')).toBe(CALLBACK_URI)
    expect(login.location.searchParams.get('response_type')).toBe('code')
    expect(login.location.searchParams.get('scope')).toBe('openid profile email')
    expect(login.location.searchParams.get('code_challenge_method')).toBe('S256')
    expect(login.location.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(login.location.searchParams.get('state')).toBeTruthy()
    expect(login.location.searchParams.get('nonce')).toBeTruthy()

    const callback = await completeLogin(provider, login)
    expect(callback.status).toBe(303)
    expect(stringHeader(callback, 'location')).toBe('/quotes/current?tab=review')
    expect(issuer.pkceVerified).toBe(true)
    const sessionCookie = responseCookie(callback, 'dsh_oidc_session')
    const opaqueValue = sessionCookie.split('=', 2)[1]
    expect(opaqueValue).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(opaqueValue).not.toContain('.')

    const context = await provider.authenticate({
      url: '/api',
      headers: { host: APP_HOST, cookie: sessionCookie },
    })
    expect(Object.keys(context.principal).sort()).toEqual([
      'authenticatedAt',
      'displayName',
      'email',
      'issuer',
      'principalId',
      'subject',
    ])
    expect(context.principal).toMatchObject({
      issuer: issuer.issuer,
      subject: 'alice',
      displayName: 'Alice Example',
      email: 'alice@example.test',
    })
    expect(JSON.stringify(context)).not.toContain('opaque-access')
    expect(JSON.stringify(context)).not.toContain('private_role')
    await expect(provider.authenticate({
      url: '/api',
      headers: { host: APP_HOST, cookie: 'dsh_oidc_session=forged' },
    })).rejects.toMatchObject({ status: 401 })
  })

  it.each([
    ['state', 'state', 401],
    ['PKCE', 'pkce', 401],
    ['nonce', 'nonce', 401],
    ['issuer', 'issuer', 401],
    ['audience', 'audience', 401],
    ['expiration', 'expired', 401],
    ['JWS', 'signature', 401],
    ['missing introspection authority', 'introspection-missing', 401],
    ['introspection issuer', 'introspection-issuer', 401],
    ['introspection audience', 'introspection-audience', 401],
    ['introspection client', 'introspection-client', 401],
    ['introspection subject', 'introspection-subject', 401],
    ['introspection expiration', 'introspection-expired', 401],
    ['provider outage', 'token-outage', 503],
    ['provider rate limit', 'token-rate-limit', 503],
    ['provider server error', 'token-server-error', 503],
    ['provider transient error', 'token-transient', 503],
  ] as const)('fails closed for invalid %s', async (_label, mode, expectedStatus) => {
    issuer.mode = mode === 'state' ? 'valid' : mode
    issuer.introspectionActive = true
    issuer.introspectionOutage = false
    const provider = await createProvider()
    const login = await beginLogin(provider)
    const callback = await completeLogin(provider, login, mode === 'state' ? 'forged-state' : undefined)
    expect(callback.status).toBe(expectedStatus)
    expect(callback.body).not.toContain('authorization-code')
    expect(() => responseCookie(callback, 'dsh_oidc_session')).toThrow()
  })

  it('rejects discovery whose returned issuer differs from the configured issuer', async () => {
    issuer.discoveryIssuerOverride = `${issuer.issuer}/other`
    await expect(createProvider()).rejects.toThrow()
    issuer.discoveryIssuerOverride = undefined
  })

  it('limits the explicit insecure-HTTP escape hatch to loopback development URLs', async () => {
    const config = providerConfig()
    config.issuer = 'http://identity.example.test/realms/cpq'
    await expect(OidcPrincipalProvider.create(new Context(), config))
      .rejects.toThrow('HTTP requires explicit loopback development mode')
  })

  it('aborts active contexts when introspection reports revocation or becomes unavailable', async () => {
    const revokedProvider = await createProvider()
    const revoked = await activeSession(revokedProvider)
    issuer.introspectionActive = false
    await expect(revokedProvider.revalidate(revoked.context)).rejects.toMatchObject({ status: 401 })
    expect(revoked.context.invalidated.aborted).toBe(true)
    await expect(revokedProvider.authenticate({
      url: '/api',
      headers: { host: APP_HOST, cookie: revoked.cookie },
    })).rejects.toMatchObject({ status: 401 })

    issuer.introspectionActive = true
    issuer.introspectionOutage = false
    const unavailableProvider = await createProvider()
    const unavailable = await activeSession(unavailableProvider)
    issuer.introspectionOutage = true
    await expect(unavailableProvider.revalidate(unavailable.context)).rejects.toMatchObject({ status: 503 })
    expect(unavailable.context.invalidated.aborted).toBe(true)
    issuer.introspectionOutage = false
  })

  it.each([
    ['timeout', 'TimeoutError'],
    ['abort', 'AbortError'],
  ] as const)('returns 503 when token exchange ends in an openid-client %s', async (_label, errorName) => {
    issuer.mode = 'valid'
    const provider = await createProvider()
    const login = await beginLogin(provider)
    const configuration = Reflect.get(provider, 'oidc') as Configuration
    configuration[customFetch] = async () => { throw new DOMException('fixture provider failure', errorName) }

    const callback = await completeLogin(provider, login)
    expect(callback.status).toBe(503)
    expect(callback.body).toBe('identity provider unavailable')
    expect(() => responseCookie(callback, 'dsh_oidc_session')).toThrow()
  })

  it('does not establish a session after matching back-channel logout wins the callback race', async () => {
    issuer.mode = 'valid'
    issuer.introspectionActive = true
    issuer.introspectionOutage = false
    const provider = await createProvider()
    const login = await beginLogin(provider)
    const pause = issuer.pauseNextIntrospection()
    const callbackPending = completeLogin(provider, login)
    try {
      await pause.entered
      const logoutToken = await issuer.logoutToken({ sid: 'sid-1', jti: 'logout-during-callback' })
      await provider.processBackchannelLogout(logoutToken)
    } finally {
      pause.release()
    }

    const callback = await callbackPending
    expect(callback.status).toBe(401)
    expect(callback.body).toBe('unauthorized')
    expect(() => responseCookie(callback, 'dsh_oidc_session')).toThrow()
  })

  it('rolls back a newly established session when the callback response fails', async () => {
    issuer.mode = 'valid'
    issuer.introspectionActive = true
    issuer.introspectionOutage = false
    const provider = await createProvider()
    const login = await beginLogin(provider)
    const response = new FailFirstEndResponse()
    await provider.handleCallback({
      method: 'GET',
      url: `${CALLBACK_PATH}?code=authorization-code&state=${encodeURIComponent(login.location.searchParams.get('state') ?? '')}`,
      headers: { host: APP_HOST, cookie: login.transactionCookie },
    }, response)

    expect(response.status).toBe(401)
    const issued = response.setCookieHistory.flatMap(value => typeof value === 'string' ? [value] : value)
      .find(value => value.startsWith('dsh_oidc_session=') && !value.startsWith('dsh_oidc_session=;'))
    expect(issued).toBeDefined()
    await expect(provider.authenticate({
      url: '/api',
      headers: { host: APP_HOST, cookie: issued?.split(';', 1)[0] ?? '' },
    })).rejects.toMatchObject({ status: 401 })
  })

  it('supports local/RP logout and signed replay-safe back-channel logout', async () => {
    const provider = await createProvider()
    const front = await activeSession(provider)
    const get = new TestResponse()
    provider.handleLogout({
      method: 'GET',
      url: '/.dsh/oidc/logout',
      headers: { host: APP_HOST, cookie: front.cookie, origin: APP_ORIGIN },
    }, get)
    expect(get.status).toBe(405)
    expect(get.header('allow')).toBe('POST')
    expect(front.context.invalidated.aborted).toBe(false)

    const crossSite = new TestResponse()
    provider.handleLogout({
      method: 'POST',
      url: '/.dsh/oidc/logout',
      headers: { host: APP_HOST, cookie: front.cookie, origin: 'https://attacker.example' },
    }, crossSite)
    expect(crossSite.status).toBe(403)
    expect(front.context.invalidated.aborted).toBe(false)

    const logout = new TestResponse()
    provider.handleLogout({
      method: 'POST',
      url: '/.dsh/oidc/logout',
      headers: { host: APP_HOST, cookie: front.cookie, origin: APP_ORIGIN },
    }, logout)
    expect(logout.status).toBe(303)
    const logoutLocation = new URL(stringHeader(logout, 'location'))
    expect(logoutLocation.href).toContain(`${issuer.issuer}/logout`)
    expect(logoutLocation.searchParams.get('post_logout_redirect_uri')).toBe(`${APP_ORIGIN}/signed-out`)
    expect(logoutLocation.searchParams.has('id_token_hint')).toBe(false)
    expect(front.context.invalidated.aborted).toBe(true)

    const back = await activeSession(provider)
    const wrongAudience = await issuer.logoutToken({ sid: 'sid-1', audience: 'other-client', jti: 'wrong-aud' })
    await expect(provider.processBackchannelLogout(wrongAudience)).rejects.toThrow()
    expect(back.context.invalidated.aborted).toBe(false)
    const logoutToken = await issuer.logoutToken({ sid: 'sid-1', jti: 'logout-1' })
    await provider.processBackchannelLogout(logoutToken)
    expect(back.context.invalidated.aborted).toBe(true)
    await expect(provider.processBackchannelLogout(logoutToken)).rejects.toThrow('replayed')
  })

  it('retains replay hashes for every instant when the original logout token remains valid', async () => {
    const provider = await createProvider()
    await provider.processBackchannelLogout(await issuer.logoutToken({ sid: 'jwks-warmup', jti: 'jwks-warmup' }))
    logoutTokenIds(provider).clear()
    logoutTargets(provider).clear()

    const issuedAt = Math.floor(Date.now() / 1_000)
    const age301 = await issuer.logoutToken({ sid: 'age-301', jti: 'age-301', issuedAt })
    const age330 = await issuer.logoutToken({ sid: 'age-330', jti: 'age-330', issuedAt })
    const age331 = await issuer.logoutToken({ sid: 'age-331', jti: 'age-331', issuedAt })
    const futureBoundary = await issuer.logoutToken({
      sid: 'future-boundary',
      jti: 'future-boundary',
      issuedAt: issuedAt + 30,
    })
    const futureRejected = await issuer.logoutToken({
      sid: 'future-rejected',
      jti: 'future-rejected',
      issuedAt: issuedAt + 31,
    })

    vi.useFakeTimers()
    try {
      vi.setSystemTime(issuedAt * 1_000)
      await provider.processBackchannelLogout(age301)
      await provider.processBackchannelLogout(age330)
      await provider.processBackchannelLogout(futureBoundary)
      await expect(provider.processBackchannelLogout(futureRejected)).rejects.toThrow(/should be in the past/u)

      const futureId = createHash('sha256').update('future-boundary').digest('base64url')
      expect(logoutTokenIds(provider).get(futureId)).toBeGreaterThanOrEqual((issuedAt + 361) * 1_000)

      vi.setSystemTime((issuedAt + 301) * 1_000)
      await expect(provider.processBackchannelLogout(age301)).rejects.toThrow('logout token replayed')
      vi.setSystemTime((issuedAt + 330) * 1_000)
      await expect(provider.processBackchannelLogout(age330)).rejects.toThrow('logout token replayed')
      vi.setSystemTime((issuedAt + 331) * 1_000)
      await expect(provider.processBackchannelLogout(age331)).rejects.toThrow(/too far in the past/u)
    } finally {
      vi.useRealTimers()
    }
  })

  it('rejects new logout tokens when replay capacity is full without evicting prior hashes', async () => {
    const provider = await createProvider({ maxSessions: 1 })
    const retainedTokens = await Promise.all(([
      ['retained-target-1', 'retained-1'],
      ['retained-target-2', 'retained-2'],
    ] as const).map(([sid, jti]) => (
      issuer.logoutToken({ sid, jti })
    )))
    for (const token of retainedTokens) {
      await provider.processBackchannelLogout(token)
    }
    const ids = logoutTokenIds(provider)
    const targets = logoutTargets(provider)
    const idsBefore = [...ids]
    const targetsBefore = [...targets]

    const rejected = await issuer.logoutToken({ sid: 'retained-target-1', jti: 'capacity-direct' })
    await expect(provider.processBackchannelLogout(rejected)).rejects.toMatchObject({
      code: 'principal-unavailable',
      status: 503,
      message: 'back-channel logout capacity unavailable',
    })
    const routeRejected = await issuer.logoutToken({ sid: 'retained-target-1', jti: 'capacity-route' })
    expect((await postBackchannelLogout(provider, routeRejected)).status).toBe(503)

    expect([...ids]).toEqual(idsBefore)
    expect([...targets]).toEqual(targetsBefore)
    expect(ids.size).toBe(2)
    for (const token of retainedTokens) {
      await expect(provider.processBackchannelLogout(token)).rejects.toThrow('logout token replayed')
    }
  })

  it('rejects a new target at tombstone capacity with no replay or session side effects', async () => {
    const provider = await createProvider({ maxSessions: 1 })
    for (const [sid, jti] of [
      ['retained-target-1', 'target-token-1'],
      ['retained-target-2', 'target-token-2'],
    ] as const) {
      await provider.processBackchannelLogout(await issuer.logoutToken({ sid, jti }))
    }
    const ids = logoutTokenIds(provider)
    const targets = logoutTargets(provider)
    ids.clear()
    const targetsBefore = [...targets]
    const session = await activeSession(provider)

    const rejected = await issuer.logoutToken({ sid: 'sid-1', jti: 'target-capacity' })
    await expect(provider.processBackchannelLogout(rejected)).rejects.toMatchObject({
      code: 'principal-unavailable',
      status: 503,
    })

    expect([...ids]).toEqual([])
    expect([...targets]).toEqual(targetsBefore)
    expect(targets.has('sid\0sid-1')).toBe(false)
    expect(session.context.invalidated.aborted).toBe(false)
    await expect(provider.authenticate({
      url: '/api',
      headers: { host: APP_HOST, cookie: session.cookie },
    })).resolves.toBe(session.context)
  })

  it('stores only one fixed-length hash for a very long logout token id', async () => {
    const provider = await createProvider({ maxSessions: 1 })
    const jti = 'raw-jti-'.repeat(1_000)
    await provider.processBackchannelLogout(await issuer.logoutToken({ sid: 'sid-1', jti }))
    const ids = logoutTokenIds(provider)
    expect(ids.size).toBe(1)
    expect([...ids.keys()]).toEqual([expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u)])
    expect([...ids.keys()].some(id => id.includes('raw-jti'))).toBe(false)
  })

  it('maps an unavailable remote JWKS to Principal provider unavailability', async () => {
    const provider = await createProvider()
    const token = await issuer.logoutToken({ sid: 'sid-1', jti: 'jwks-outage' })
    issuer.jwksOutage = true
    try {
      await expect(provider.processBackchannelLogout(token)).rejects.toMatchObject({
        code: 'principal-unavailable',
        status: 503,
      })
    } finally {
      issuer.jwksOutage = false
    }
  })
})

function json(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json' })
  response.end(JSON.stringify(value))
}

async function requestBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array))
  return Buffer.concat(chunks).toString('utf8')
}

function stringHeader(response: TestResponse, name: string): string {
  const value = response.header(name)
  if (typeof value !== 'string') throw new Error(`missing ${name} response header`)
  return value
}

function responseCookie(response: TestResponse, name: string): string {
  const value = response.header('set-cookie')
  const values = typeof value === 'string' ? [value] : value ?? []
  const match = values.find(entry => entry.startsWith(`${name}=`) && !entry.startsWith(`${name}=;`))
  if (match === undefined) throw new Error(`missing ${name} response cookie`)
  return match.split(';', 1)[0]!
}

it('uses stable authentication errors without leaking protocol material', () => {
  const error = new PrincipalAuthenticationError('principal-unauthenticated', 401, 'unauthorized')
  expect(error).toMatchObject({ code: 'principal-unauthenticated', status: 401 })
})
