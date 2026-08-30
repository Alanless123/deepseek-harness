/** Host registry and HTTP adapter for generic Connection RPC channels. */

import { Context, Service } from '@deepseek-ai/cordis'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import {
  RpcId,
  type ClientRequest,
  type RpcId as RpcIdType,
} from './rpc.ts'
import { clientRequestSchema } from './rpc-schema.ts'
import { bridge } from './http-bridge.ts'
import { isTrustedApiRequest } from './api-request-trust.ts'
import { API_PATH } from './api-path.ts'
import type { BrowserAuth } from './browser-auth.ts'
import { PrincipalAuthenticationError, assertPrincipalContextActive, type AuthenticatedPrincipalContext, type PrincipalContextService, type PrincipalProvider } from '@deepseek-ai/dsh-principal'
import type {
  ConnectionIndexRequest,
  ConnectionIndexResponse,
  ConnectionFetchRoute,
  ConnectionFetchHandler,
  HostConnectionFetch,
  ConnectionRpcEndpointMatcher,
  ConnectionRpcFailure,
  ConnectionRpcHandler,
  ConnectionRpcResult,
  ConnectionRequestRejection,
  ConnectionRequestAuthentication,
  ConnectionRequestContext,
  ConnectionTrustRequest,
  HostConnectionHandle,
  HostConnectionRpc,
} from './rpc.ts'

const INVALID_REQUEST_RPC_ID = RpcId('invalid-request')
const CHANNEL_PATTERN = /^\/[A-Za-z0-9._~-]+$/
const ENDPOINT_SEGMENT_PATTERN = /^[A-Za-z0-9_$.-]+$/

interface ConnectionRpcInterceptor {
  readonly matches: ConnectionRpcEndpointMatcher
  readonly fetchHandler: ConnectionFetchHandler
}

interface RegisteredFetchRoute {
  readonly methods: ReadonlySet<string>
  readonly fetch: ConnectionFetchRoute['fetch']
}

interface HostPrincipalOptions {
  readonly principalMode?: 'legacy' | 'required'
  readonly principalProvider?: () => PrincipalProvider | undefined
  readonly principals?: () => PrincipalContextService | undefined
}

interface ConnectionServerResponse {
  readonly type: 'server-response'
  readonly rpcId: RpcIdType
  readonly result: ConnectionRpcResult<unknown>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Host Connection transport and RPC registrations. */
    connection: HostConnectionHandle
  }
}

/** Host Connection service whose channel registrations belong to the caller fiber. */
export class HostConnectionService extends Service implements HostConnectionHandle {
  private readonly interceptors = new Map<string, ConnectionRpcInterceptor>()
  private readonly fetchRoutes = new Map<string, RegisteredFetchRoute>()

  /**
   * Provide the Host half over the active HTTP server.
   * @param ctx - owning Connection plugin context.
   * @param trustedHosts - deployment authorities accepted by the Host/Origin fence.
   * @param browserAuth - process token and persistent browser-session owner;
   *   omitted when an authenticated Principal provider owns the index/session.
   */
  constructor(
    ctx: Context,
    private readonly trustedHosts: readonly string[],
    private readonly browserAuth: BrowserAuth | undefined,
    private readonly principalOptions: HostPrincipalOptions = {},
  ) {
    super(ctx, 'connection')
  }

  /** Generic channel registry scoped to the Context reading this service. */
  get rpc(): HostConnectionRpc {
    const owner = this.ctx
    return {
      handle: (channel, handler) => this.register(owner, channel, handler),
      intercept: (channel, matches, handler) =>
        this.registerInterceptor(owner, channel, matches, handler),
    }
  }

  /** Exact Fetch-route registry scoped to the Context reading this service. */
  get fetch(): HostConnectionFetch {
    const owner = this.ctx
    return {
      register: route => this.registerFetchRoute(owner, route),
    }
  }

  /** Apply the configured Host/Origin fence, then browser authentication. */
  requestRejection(request: ConnectionTrustRequest): ConnectionRequestRejection {
    if (!isTrustedApiRequest(request, this.trustedHosts)) return 403
    if (this.principalOptions.principalMode === 'required') return 503
    return this.requireBrowserAuth().isAuthenticated(request) ? undefined : 401
  }

  /** Authenticate before request decoding and mint the Host-only dispatch context. */
  async authenticateRequest(request: ConnectionTrustRequest): Promise<ConnectionRequestAuthentication> {
    if (!isTrustedApiRequest(request, this.trustedHosts)) return { ok: false, rejection: 403 }
    if (this.principalOptions.principalMode !== 'required') {
      return this.requireBrowserAuth().isAuthenticated(request)
        ? { ok: true, context: {} }
        : { ok: false, rejection: 401 }
    }
    const provider = this.principalOptions.principalProvider?.()
    const principals = this.principalOptions.principals?.()
    if (provider === undefined || principals === undefined) return { ok: false, rejection: 503 }
    try {
      const context = await provider.authenticate(request)
      assertPrincipalContextActive(context)
      return { ok: true, context }
    } catch (error) {
      if (error instanceof PrincipalAuthenticationError) return { ok: false, rejection: error.status }
      return { ok: false, rejection: 503 }
    }
  }

  /** Revalidate one active WebSocket generation without accepting replacement Browser identity. */
  async revalidateRequest(context: ConnectionRequestContext): Promise<ConnectionRequestRejection> {
    if (this.principalOptions.principalMode !== 'required') return undefined
    if (context.principal === undefined) return 401
    const provider = this.principalOptions.principalProvider?.()
    const principals = this.principalOptions.principals?.()
    if (provider === undefined || principals === undefined) return 503
    try {
      await provider.revalidate(context as AuthenticatedPrincipalContext)
      return undefined
    } catch (error) {
      if (error instanceof PrincipalAuthenticationError) return error.status
      return 503
    }
  }

  /** Enter Principal ALS only for contexts created by the Host authenticator. */
  runWithRequestContext<T>(context: ConnectionRequestContext, callback: () => T): T {
    if (context.principal === undefined) {
      if (this.principalOptions.principalMode === 'required') {
        throw new PrincipalAuthenticationError(
          'principal-unauthenticated',
          401,
          'authenticated Principal is required',
        )
      }
      return callback()
    }
    const principals = this.principalOptions.principals?.()
    if (principals === undefined) throw new PrincipalAuthenticationError('principal-unavailable', 503, 'Principal context service is unavailable')
    return principals.run(context as AuthenticatedPrincipalContext, callback)
  }

  /** Authenticate an index request through the process-token exchange or cookie. */
  authorizeIndex(request: ConnectionIndexRequest, response: ConnectionIndexResponse): boolean | Promise<boolean> {
    if (this.principalOptions.principalMode === 'required') {
      const provider = this.principalOptions.principalProvider?.()
      if (provider === undefined) {
        response.writeHead(503, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' })
        response.end('identity provider unavailable')
        return false
      }
      return provider.authorizeIndex(request, response)
    }
    return this.requireBrowserAuth().authorizeIndex(request, response)
  }

  /**
   * Resolve the browser entry URL without exposing a legacy launch token when
   * this Host delegates index authentication to an authenticated Principal
   * provider. OIDC owns that redirect and session; BrowserAuth is neither
   * needed nor permitted on the public startup URL in this mode.
   */
  authenticatedUrl(baseUrl: string): string {
    if (this.principalOptions.principalMode === 'required') {
      const url = new URL(baseUrl)
      url.pathname = '/'
      url.search = ''
      url.hash = ''
      return url.href
    }
    return this.requireBrowserAuth().authenticatedUrl(baseUrl)
  }

  private requireBrowserAuth(): BrowserAuth {
    if (this.browserAuth === undefined) {
      throw new Error('connection: BrowserAuth is unavailable in required Principal mode')
    }
    return this.browserAuth
  }

  /**
   * Compose one shared-channel Fetch handler from exact routes and its interceptor.
   * @param channel - shared channel mounted by Connection.
   * @returns Fetch handler that selects one owner or returns 404.
   */
  createSharedFetchHandler(
    channel: '/api',
  ): ConnectionFetchHandler {
    return {
      fetch: async (request, context = {}) => this.runWithRequestContext(context, async () => {
        const pathname = new URL(request.url).pathname
        const route = this.fetchRoutes.get(pathname)
        if (route?.methods.has(request.method) === true) return route.fetch(request, context)
        const endpoint = endpointFromPath(channel, pathname)
        const interceptor = this.interceptors.get(channel)
        if (endpoint === undefined || interceptor === undefined || !interceptor.matches(endpoint)) {
          return new Response('not found', { status: 404 })
        }
        return interceptor.fetchHandler.fetch(request, context)
      }),
    }
  }

  private registerFetchRoute(
    owner: Context,
    route: ConnectionFetchRoute,
  ): () => Promise<void> {
    assertFetchRoute(route)
    const registered: RegisteredFetchRoute = {
      methods: new Set(route.methods),
      fetch: route.fetch,
    }
    return owner.effect(() => {
      if (this.fetchRoutes.has(route.path)) {
        throw new Error(`connection: exact Fetch route ${JSON.stringify(route.path)} is already registered`)
      }
      this.fetchRoutes.set(route.path, registered)
      return () => { this.fetchRoutes.delete(route.path) }
    }, `client-connection: ${route.path} Fetch route`)
  }

  private register(
    owner: Context,
    channel: string,
    handler: ConnectionRpcHandler,
  ): () => Promise<void> {
    assertChannel(channel)
    const fetchHandler = rpcFetchHandler(channel, handler)
    const route: WebRoute = {
      kind: 'prefix',
      path: channel,
      handler: async (req, res) => {
        const authentication = await this.authenticateRequest(req)
        if (!authentication.ok) {
          res.writeHead(authentication.rejection)
          res.end(rejectionBody(authentication.rejection))
          return
        }
        await bridge(req, res, {
          fetch: request => this.runWithRequestContext(
            authentication.context,
            () => fetchHandler.fetch(request, authentication.context),
          ),
        })
      },
    }
    return owner.effect(
      () => owner.webServer.register(route),
      `client-connection: ${channel} rpc channel`,
    )
  }

  private registerInterceptor(
    owner: Context,
    channel: string,
    matches: ConnectionRpcEndpointMatcher,
    handler: ConnectionRpcHandler,
  ): () => Promise<void> {
    if (channel !== API_PATH) {
      throw new Error(`connection: invalid shared RPC channel ${JSON.stringify(channel)}`)
    }
    const interceptor: ConnectionRpcInterceptor = {
      matches,
      fetchHandler: rpcFetchHandler(channel, handler),
    }
    return owner.effect(() => {
      if (this.interceptors.has(channel)) {
        throw new Error(`connection: shared RPC channel ${JSON.stringify(channel)} already has an interceptor`)
      }
      this.interceptors.set(channel, interceptor)
      return () => {
        this.interceptors.delete(channel)
      }
    }, `client-connection: ${channel} rpc interceptor`)
  }
}

function rpcFetchHandler(
  channel: string,
  handler: ConnectionRpcHandler,
): ConnectionFetchHandler {
  return {
    async fetch(request: Request, context: ConnectionRequestContext = {}): Promise<Response> {
      const endpoint = endpointFromPath(channel, new URL(request.url).pathname)
      if (request.method !== 'POST' || endpoint === undefined) {
        return new Response('not found', { status: 404 })
      }

      const mediaType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
      if (mediaType !== 'application/json') {
        return new Response('content type must be application/json', { status: 415 })
      }

      let body: unknown
      try {
        body = await request.json()
      } catch {
        return new Response('body is not JSON', { status: 400 })
      }

      const envelope = clientRequestSchema.safeParse(body)
      if (!envelope.success) {
        return invalidEnvelopeResponse(body, envelope.error.issues)
      }
      const message: ClientRequest = envelope.data
      if (message.method !== endpoint) {
        return errorResponse(message.rpcId, {
          code: 'bad-request',
          message: `method ${JSON.stringify(message.method)} does not match endpoint ${JSON.stringify(endpoint)}`,
          details: { issues: [] },
        })
      }

      try {
        const result = await handler(endpoint, message.payload, request.signal, context)
        return fullResponse(message.rpcId, result)
      } catch (error) {
        const status = authorizationStatus(error)
        if (status !== undefined) return new Response(rejectionBody(status), { status })
        return new Response('handler failure', { status: 500 })
      }
    },
  }
}

function authorizationStatus(error: unknown): 401 | 403 | 503 | undefined {
  if (typeof error !== 'object' || error === null || !('status' in error)) return undefined
  const status = (error as { readonly status?: unknown }).status
  return status === 401 || status === 403 || status === 503 ? status : undefined
}

function rejectionBody(status: 401 | 403 | 503): string {
  if (status === 401) return 'unauthorized'
  if (status === 403) return 'forbidden'
  return 'identity provider unavailable'
}

function invalidEnvelopeResponse(body: unknown, issues: readonly object[]): Response {
  const rawId = (body as { rpcId?: unknown } | null)?.rpcId
  const rpcId = typeof rawId === 'string' ? RpcId(rawId) : INVALID_REQUEST_RPC_ID
  return errorResponse(rpcId, {
    code: 'bad-request',
    message: 'invalid client-request message',
    details: { issues },
  })
}

function endpointFromPath(channel: string, pathname: string): string | undefined {
  if (!pathname.startsWith(`${channel}/`)) return undefined
  const endpoint = pathname.slice(channel.length + 1)
  const segments = endpoint.split('/')
  if (segments.some(segment =>
    segment === '' || segment === '.' || segment === '..' || !ENDPOINT_SEGMENT_PATTERN.test(segment))) {
    return undefined
  }
  return endpoint
}

function errorResponse(rpcId: RpcIdType, error: ConnectionRpcFailure): Response {
  return fullResponse(rpcId, { ok: false, error })
}

function fullResponse(rpcId: RpcIdType, result: ConnectionRpcResult<unknown>): Response {
  const body: ConnectionServerResponse = { type: 'server-response', rpcId, result }
  return Response.json(body)
}

function assertChannel(channel: string): void {
  if (!CHANNEL_PATTERN.test(channel) || channel === '/api') {
    throw new Error(`connection: invalid or reserved RPC channel ${JSON.stringify(channel)}`)
  }
}

function assertFetchRoute(route: ConnectionFetchRoute): void {
  if (endpointFromPath(API_PATH, route.path) === undefined) {
    throw new Error(`connection: invalid exact Fetch route ${JSON.stringify(route.path)}`)
  }
  if (route.methods.length === 0) {
    throw new Error(`connection: exact Fetch route ${JSON.stringify(route.path)} declares no methods`)
  }
  const methods = new Set(route.methods)
  if (methods.size !== route.methods.length) {
    throw new Error(`connection: exact Fetch route ${JSON.stringify(route.path)} repeats a method`)
  }
}
