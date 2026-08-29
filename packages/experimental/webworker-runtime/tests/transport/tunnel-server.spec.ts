import { describe, expect, it, vi } from 'vitest'
import type { TunnelOutboundFrame } from '../../src/transport/frames.ts'
import { TunnelServer, type TunnelSeams } from '../../src/transport/tunnel.ts'

function harness(): { server: TunnelServer; frames: TunnelOutboundFrame[] } {
  const frames: TunnelOutboundFrame[] = []
  const server = new TunnelServer({
    port: { postMessage: (frame) => { frames.push(frame) } },
    requestListener: () => Promise.reject(new Error('fixture has no HTTP listener')),
  })
  return { server, frames }
}

function seams(openStream: TunnelSeams['openStream']): TunnelSeams {
  return {
    directFetch: () => Promise.reject(new Error('fixture has no direct fetch')),
    bootPayload: () => ({}),
    openStream,
    streamFailure: error => ({
      code: 'fixture-stream-failed',
      message: error instanceof Error ? error.message : String(error),
      details: { fixture: true },
    }),
    allowUnauthenticatedOwnedPageBypass: true,
  }
}

describe('worker tunnel unary authentication', () => {
  it.each([401, 403])('retries a route-lane HTTP %s through the worker-local direct lane', async (status) => {
    const frames: TunnelOutboundFrame[] = []
    const directFetch = vi.fn(async () => new Response('direct answer', {
      status: 200,
      headers: { 'content-type': 'text/plain' },
    }))
    const server = new TunnelServer({
      port: { postMessage: (frame) => { frames.push(frame) } },
      requestListener: () => Promise.resolve((_req, response) => {
        const res = response as {
          writeHead(status: number, headers: Record<string, string>): void
          end(body: string): void
        }
        res.writeHead(status, { 'content-type': 'text/plain' })
        res.end('network request rejected')
      }),
    })
    server.serve({
      ...seams(async () => (async function *(): AsyncGenerator { yield undefined })()),
      directFetch,
    })

    server.handleMessage({
      t: 'req', id: status, method: 'POST', url: 'http://localhost/api/session/list', headers: {},
    })

    await vi.waitFor(() => { expect(frames).toHaveLength(1) })
    const [frame] = frames
    expect(frame).toMatchObject({ t: 'res', id: status, status: 200 })
    if (frame?.t !== 'res' || frame.body === undefined) throw new Error('direct retry did not return one body')
    expect(new TextDecoder().decode(frame.body)).toBe('direct answer')
    expect(directFetch).toHaveBeenCalledOnce()
  })

  it('does not retry a route-lane 503 through the direct lane', async () => {
    const frames: TunnelOutboundFrame[] = []
    const directFetch = vi.fn(async () => new Response('unexpected direct answer'))
    const server = new TunnelServer({
      port: { postMessage: (frame) => { frames.push(frame) } },
      requestListener: () => Promise.resolve((_req, response) => {
        const res = response as { writeHead(status: number): void; end(body: string): void }
        res.writeHead(503)
        res.end('identity provider unavailable')
      }),
    })
    server.serve({
      ...seams(async () => (async function *(): AsyncGenerator { yield undefined })()),
      directFetch,
    })

    server.handleMessage({
      t: 'req', id: 503, method: 'POST', url: 'http://localhost/api/session/list', headers: {},
    })

    await vi.waitFor(() => { expect(frames).toHaveLength(1) })
    expect(frames[0]).toMatchObject({ t: 'res', id: 503, status: 503 })
    expect(directFetch).not.toHaveBeenCalled()
  })

  it.each([
    ['a route-lane 401 retry', {}],
    ['the configured direct lane', { unaryApiLane: 'direct' as const }],
    ['a privileged method', { privilegedMethods: new Set(['session/list']) }],
  ])('fails %s closed when Principal authentication owns the carrier', async (_label, options) => {
    const frames: TunnelOutboundFrame[] = []
    const directFetch = vi.fn(async () => new Response('unexpected direct answer'))
    const server = new TunnelServer({
      port: { postMessage: (frame) => { frames.push(frame) } },
      requestListener: () => Promise.resolve((_req, response) => {
        const res = response as { writeHead(status: number): void; end(body: string): void }
        res.writeHead(401)
        res.end('login required')
      }),
      ...options,
    })
    server.serve({
      ...seams(async () => (async function *(): AsyncGenerator { yield undefined })()),
      directFetch,
      allowUnauthenticatedOwnedPageBypass: false,
    })

    server.handleMessage({
      t: 'req', id: 504, method: 'POST', url: 'http://localhost/api/session/list', headers: {},
    })

    await vi.waitFor(() => { expect(frames).toHaveLength(1) })
    expect(frames[0]).toMatchObject({ t: 'res', id: 504, status: 503 })
    expect(directFetch).not.toHaveBeenCalled()
  })
})

describe('worker tunnel logical streams', () => {
  it('drains a pre-boot open through the worker-local Gateway seam', async () => {
    const { server, frames } = harness()
    const seen: unknown[] = []
    server.handleMessage({
      t: 'stream-open', id: 1, endpoint: 'session/follow', payload: { args: { sessionId: 'session-1' } },
    })
    expect(frames).toEqual([])

    server.serve(seams(async (endpoint, payload, signal) => {
      seen.push(endpoint, payload, signal)
      return (async function *(): AsyncGenerator {
        yield { type: 'baseline' }
        yield { type: 'event', seq: 1 }
      })()
    }))

    await vi.waitFor(() => {
      expect(frames).toEqual([
        { t: 'stream-item', id: 1, value: { type: 'baseline' } },
        { t: 'stream-item', id: 1, value: { type: 'event', seq: 1 } },
        { t: 'stream-end', id: 1 },
      ])
    })
    expect(seen).toEqual([
      'session/follow',
      { args: { sessionId: 'session-1' } },
      expect.any(AbortSignal),
    ])
  })

  it('cancels one logical stream without emitting a terminal frame', async () => {
    const { server, frames } = harness()
    const opened = Promise.withResolvers<AbortSignal>()
    const stopped = Promise.withResolvers<undefined>()
    server.serve(seams(async (_endpoint, _payload, signal) => {
      opened.resolve(signal)
      return (async function *(): AsyncGenerator {
        yield 'ready'
        await new Promise<void>((resolve) => {
          signal.addEventListener('abort', () => { resolve() }, { once: true })
        })
        stopped.resolve(undefined)
      })()
    }))
    server.handleMessage({ t: 'stream-open', id: 2, endpoint: '$events', payload: { args: {} } })
    const signal = await opened.promise
    await vi.waitFor(() => { expect(frames).toContainEqual({ t: 'stream-item', id: 2, value: 'ready' }) })

    server.handleMessage({ t: 'abort', id: 2 })
    await stopped.promise
    expect(signal.aborted).toBe(true)
    expect(frames).toEqual([{ t: 'stream-item', id: 2, value: 'ready' }])
  })

  it('maps a Host stream failure through Gateway-owned fields', async () => {
    const { server, frames } = harness()
    server.serve(seams(async () => { throw new Error('Host stream exploded') }))
    server.handleMessage({ t: 'stream-open', id: 3, endpoint: 'probe/watch', payload: {} })

    await vi.waitFor(() => {
      expect(frames).toEqual([{
        t: 'stream-error',
        id: 3,
        failure: {
          kind: 'remote',
          code: 'fixture-stream-failed',
          message: 'Host stream exploded',
          details: { fixture: true },
        },
      }])
    })
  })

  it('refuses Principal-required streams before the worker-local opener', async () => {
    const { server, frames } = harness()
    const openStream = vi.fn(async () => (async function *(): AsyncGenerator { yield 'unexpected' })())
    server.serve({
      ...seams(openStream),
      allowUnauthenticatedOwnedPageBypass: false,
      streamFailure: error => ({
        code: (error as { status?: number }).status === 503 ? 'identity-unavailable' : 'unexpected',
        message: error instanceof Error ? error.message : String(error),
        details: { status: (error as { status?: number }).status },
      }),
    })
    server.handleMessage({ t: 'stream-open', id: 6, endpoint: 'session/follow', payload: {} })

    await vi.waitFor(() => {
      expect(frames).toEqual([{
        t: 'stream-error',
        id: 6,
        failure: {
          kind: 'remote',
          code: 'identity-unavailable',
          message: 'authenticated Principal transport is unavailable',
          details: { status: 503 },
        },
      }])
    })
    expect(openStream).not.toHaveBeenCalled()
  })

  it('refuses queued and future streams after boot failure as carrier failures', () => {
    const { server, frames } = harness()
    server.handleMessage({ t: 'stream-open', id: 4, endpoint: '$events', payload: {} })
    server.fail(new Error('image failed'))
    server.handleMessage({ t: 'stream-open', id: 5, endpoint: '$events', payload: {} })

    expect(frames).toEqual([4, 5].map(id => ({
      t: 'stream-error',
      id,
      failure: { kind: 'carrier', message: 'Error: image failed' },
    })))
  })
})
