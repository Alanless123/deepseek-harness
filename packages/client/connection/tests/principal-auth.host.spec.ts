import { Context } from '@deepseek-ai/cordis'
import {
  PrincipalAuthenticationError,
  PrincipalContextService,
  type PrincipalProvider,
  verifiedPrincipal,
} from '@deepseek-ai/dsh-principal'
import { describe, expect, it, vi } from 'vitest'
import type { BrowserAuth } from '../src/browser-auth.ts'
import { RpcId, type ClientRequest } from '../src/rpc.ts'
import { HostConnectionService } from '../src/rpc-host.ts'

function authenticatedContext() {
  return {
    principal: verifiedPrincipal({ issuer: 'https://issuer.example', subject: 'alice', displayName: 'Alice' }),
    expiresAt: Date.now() + 60_000,
    invalidated: new AbortController().signal,
    revalidateIntervalMs: 15_000,
    sessionId: 'opaque-session',
  }
}

async function mounted(provider?: PrincipalProvider) {
  const root = new Context()
  let connection!: HostConnectionService
  let principals!: PrincipalContextService
  const fiber = root.plugin((ctx) => {
    principals = new PrincipalContextService(ctx)
    connection = new HostConnectionService(ctx, [], {
      isAuthenticated: () => false,
    } as unknown as BrowserAuth, {
      principalMode: 'required',
      principalProvider: () => provider,
      principals: () => principals,
    })
  })
  await fiber.await()
  return { connection, principals, dispose: () => fiber.dispose() }
}

const trustedRequest = { headers: new Headers({ host: '127.0.0.1:3080', 'x-cpq-actor': 'forged' }) }

describe('Connection Principal authentication', () => {
  it('propagates the same Host Principal to exact Fetch, unary RPC, and ALS', async () => {
    const context = authenticatedContext()
    const authenticate = vi.fn(async () => context)
    const provider = {
      authenticate,
      authorizeIndex: vi.fn(async () => true),
    } as unknown as PrincipalProvider
    const { connection, principals, dispose } = await mounted(provider)
    const authentication = await connection.authenticateRequest(trustedRequest)
    expect(authentication.ok).toBe(true)
    if (!authentication.ok) throw new Error('authentication failed')

    let exactPrincipal = ''
    connection.fetch.register({
      path: '/api/cpq-export',
      methods: ['GET'],
      fetch: async (_request, requestContext) => {
        exactPrincipal = `${requestContext.principal?.principalId}:${principals.require().principal.principalId}`
        return new Response('ok')
      },
    })
    const shared = connection.createSharedFetchHandler('/api')
    await connection.runWithRequestContext(authentication.context, () => shared.fetch(
      new Request('http://host/api/cpq-export'),
      authentication.context,
    ))

    let unaryPrincipal = ''
    connection.rpc.intercept('/api', endpoint => endpoint === 'cpq/read', async (_endpoint, _payload, _signal, requestContext) => {
      unaryPrincipal = `${requestContext.principal?.principalId}:${principals.require().principal.principalId}`
      return { ok: true, value: null }
    })
    const message: ClientRequest = { type: 'client-request', rpcId: RpcId('principal-test'), method: 'cpq/read', payload: { actor: 'forged' } }
    await connection.runWithRequestContext(authentication.context, () => shared.fetch(new Request('http://host/api/cpq/read', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(message),
    }), authentication.context))
    const expected = `${context.principal.principalId}:${context.principal.principalId}`
    expect(exactPrincipal).toBe(expected)
    expect(unaryPrincipal).toBe(expected)
    expect(authenticate).toHaveBeenCalledOnce()
    await dispose()
  })

  it('fails closed before dispatch when the provider is missing, rejects, or fails', async () => {
    const missing = await mounted()
    await expect(missing.connection.authenticateRequest(trustedRequest)).resolves.toEqual({ ok: false, rejection: 503 })
    await missing.dispose()

    const unauthenticated = await mounted({
      authenticate: async () => { throw new PrincipalAuthenticationError('principal-unauthenticated', 401, 'login required') },
    } as unknown as PrincipalProvider)
    await expect(unauthenticated.connection.authenticateRequest(trustedRequest)).resolves.toEqual({ ok: false, rejection: 401 })
    await unauthenticated.dispose()

    const unavailable = await mounted({
      authenticate: async () => { throw new Error('introspection unavailable') },
    } as unknown as PrincipalProvider)
    await expect(unavailable.connection.authenticateRequest(trustedRequest)).resolves.toEqual({ ok: false, rejection: 503 })
    await unavailable.dispose()
  })
})
