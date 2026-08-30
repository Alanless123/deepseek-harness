/** Host WebSocket owner for multiplexed Typert Remote streams. */

import type { IncomingMessage } from 'node:http'
import { createHmac, randomBytes } from 'node:crypto'
import type { Duplex } from 'node:stream'
import WebSocket, { WebSocketServer, type RawData } from 'ws'
import type { ConnectionRequestContext } from '@deepseek-ai/dsh-client-connection'
import {
  parseRemoteStreamClientMessage,
  type RemoteStreamConnectionBinding,
  type RemoteStreamFailure,
  type RemoteStreamHelloMessage,
  type RemoteStreamServerMessage,
} from './stream-protocol.ts'

const MAX_TIMER_DELAY_MS = 2_147_483_647

/** Open one validated Remote stream for a decoded wire request. */
export type RemoteStreamOpener = (
  endpoint: string,
  payload: unknown,
  signal: AbortSignal,
  context: ConnectionRequestContext,
) => Promise<AsyncIterable<unknown>>

/** Convert an invocation or carrier failure to a stable wire value. */
export type RemoteStreamFailureMapper = (error: unknown) => RemoteStreamFailure
/** Revalidate the Host Principal bound to one accepted WebSocket generation. */
export type RemoteStreamPrincipalRevalidator = (context: ConnectionRequestContext) => Promise<void>

/** Own the no-server WebSocket acceptor and every active logical stream. */
export class RemoteStreamMuxServer {
  private readonly server = new WebSocketServer({ noServer: true })
  private readonly connections = new Set<Promise<void>>()
  private readonly bindingKey = randomBytes(32)
  private heartbeatTimer: NodeJS.Timeout | undefined

  /**
   * @param open - Gateway stream dispatcher.
   * @param failure - Gateway error-to-wire mapper.
   * @param heartbeatIntervalMs - interval between WebSocket Ping control frames.
   */
  constructor(
    private readonly open: RemoteStreamOpener,
    private readonly failure: RemoteStreamFailureMapper,
    private readonly heartbeatIntervalMs: number,
    private readonly revalidate?: RemoteStreamPrincipalRevalidator,
  ) {}

  /**
   * Upgrade one trusted request and begin serving its logical streams.
   * @param req - authenticated HTTP upgrade request.
   * @param socket - carrier socket transferred to the WebSocket server.
   * @param head - bytes already read after the HTTP upgrade headers.
   * @param context - Host-authenticated request context bound to this generation.
   */
  handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, context: ConnectionRequestContext = {}): void {
    this.server.handleUpgrade(req, socket, head, (websocket) => {
      this.startHeartbeat()
      const connection = new RemoteStreamMuxConnection(
        websocket,
        this.open,
        this.failure,
        context,
        remoteStreamHello(context, this.bindingKey),
        this.revalidate,
      )
      const done = connection.run()
      this.connections.add(done)
      void done.then(() => { this.connections.delete(done) })
    })
  }

  /** Terminate all sockets and wait until every iterator has returned. */
  async close(): Promise<void> {
    clearInterval(this.heartbeatTimer)
    this.heartbeatTimer = undefined
    for (const socket of this.server.clients) socket.terminate()
    const closed = Promise.withResolvers<void>()
    this.server.close((error) => {
      if (error === undefined) closed.resolve()
      else closed.reject(error)
    })
    await closed.promise
    await Promise.all(this.connections)
  }

  /** Start one `unref()` timer after the first upgrade; it spans empty-client periods until close(). */
  private startHeartbeat(): void {
    if (this.heartbeatTimer !== undefined) return
    this.heartbeatTimer = setInterval(() => {
      for (const socket of this.server.clients) {
        if (socket.readyState === WebSocket.OPEN) socket.ping()
      }
    }, this.heartbeatIntervalMs)
    this.heartbeatTimer.unref()
  }
}

interface ActiveStream {
  readonly abort: AbortController
  done: Promise<void>
}

class RemoteStreamMuxConnection {
  private readonly streams = new Map<string, ActiveStream>()
  private readonly lifetime = new AbortController()
  private writes = Promise.resolve()

  constructor(
    private readonly socket: WebSocket,
    private readonly open: RemoteStreamOpener,
    private readonly failure: RemoteStreamFailureMapper,
    private readonly context: ConnectionRequestContext,
    private readonly hello: RemoteStreamHelloMessage,
    private readonly revalidate?: RemoteStreamPrincipalRevalidator,
  ) {}

  async run(): Promise<void> {
    const invalidate = (): void => { this.invalidatePrincipal() }
    const closed = new Promise<void>((resolve) => {
      this.socket.once('close', resolve)
      this.socket.once('error', () => { this.socket.terminate() })
      this.socket.on('message', (data, isBinary) => {
        if (isBinary) {
          this.socket.close(1003, 'text messages required')
          return
        }
        try {
          this.receive(rawText(data))
        } catch (error) {
          if (error instanceof PrincipalInactiveError) {
            this.invalidatePrincipal()
            return
          }
          this.socket.close(1008, 'invalid Remote stream request')
        }
      })
    })
    this.context.invalidated?.addEventListener('abort', invalidate, { once: true })
    let expiration: NodeJS.Timeout | undefined
    const armExpiration = (): void => {
      const expiresAt = this.context.expiresAt
      if (expiresAt === undefined || this.lifetime.signal.aborted) return
      const remaining = expiresAt - Date.now()
      if (remaining <= 0) {
        invalidate()
        return
      }
      expiration = setTimeout(
        armExpiration,
        Math.min(MAX_TIMER_DELAY_MS, Math.max(1, Math.ceil(remaining))),
      )
      expiration.unref()
    }
    if (!this.isPrincipalActive()) invalidate()
    else armExpiration()
    let revalidationInFlight: Promise<void> | undefined
    const revalidation = this.revalidate === undefined || this.context.revalidateIntervalMs === undefined
      ? undefined
      : setInterval(() => {
        if (revalidationInFlight !== undefined) return
        const pending = this.revalidate?.(this.context).catch(invalidate).finally(() => {
          if (revalidationInFlight === pending) revalidationInFlight = undefined
        })
        revalidationInFlight = pending
      }, this.context.revalidateIntervalMs)
    revalidation?.unref()
    try {
      try {
        await this.send(this.hello)
      } catch (error) {
        if (error instanceof PrincipalInactiveError) this.invalidatePrincipal()
        else this.socket.close(1011, 'Remote stream hello could not be delivered')
      }
      await closed
      if (!this.lifetime.signal.aborted) {
        this.lifetime.abort(new Error('Remote stream socket closed'))
      }
      const active = [...this.streams.values()]
      for (const stream of active) stream.abort.abort(new Error('Remote stream socket closed'))
      await Promise.all(active.map(stream => stream.done))
    } finally {
      clearTimeout(expiration)
      clearInterval(revalidation)
      this.context.invalidated?.removeEventListener('abort', invalidate)
    }
  }

  private receive(text: string): void {
    const message = parseRemoteStreamClientMessage(text)
    if (message.type === 'cancel') {
      this.streams.get(message.streamId)?.abort.abort(new Error('Remote stream cancelled'))
      return
    }
    this.assertPrincipalActive()
    if (this.streams.has(message.streamId)) {
      throw new Error(`api gateway: duplicate Remote stream id ${JSON.stringify(message.streamId)}`)
    }
    const abort = new AbortController()
    const active: ActiveStream = {
      abort,
      done: Promise.resolve(),
    }
    this.streams.set(message.streamId, active)
    const done = this.pump(message.streamId, message.endpoint, message.payload, active)
    active.done = done
    const remove = (): void => { this.streams.delete(message.streamId) }
    void done.then(remove, remove)
  }

  private async pump(
    streamId: string,
    endpoint: string,
    payload: unknown,
    active: ActiveStream,
  ): Promise<void> {
    const signal = AbortSignal.any([active.abort.signal, this.lifetime.signal])
    try {
      this.assertPrincipalActive()
      const source = await this.open(endpoint, payload, signal, this.context)
      for await (const value of source) {
        await this.send({ type: 'item', streamId, value })
      }
      if (!signal.aborted) await this.send({ type: 'end', streamId })
    } catch (error) {
      if (error instanceof PrincipalInactiveError || !this.isPrincipalActive()) {
        this.invalidatePrincipal()
        return
      }
      if (!signal.aborted && this.socket.readyState === WebSocket.OPEN) {
        try {
          await this.send({ type: 'error', streamId, error: this.failure(error) })
        } catch (deliveryError) {
          if (deliveryError instanceof PrincipalInactiveError) {
            this.invalidatePrincipal()
            return
          }
          // A terminal frame that cannot be encoded or written leaves the
          // logical stream ambiguous, so fail the physical generation.
          this.socket.close(1011, 'Remote stream failure could not be delivered')
        }
      }
    }
  }

  private send(message: RemoteStreamServerMessage): Promise<void> {
    this.assertPrincipalActive()
    let text: string
    try {
      text = JSON.stringify(message)
    } catch (cause) {
      return Promise.reject(new Error('api gateway: Remote stream item is not JSON serializable', { cause }))
    }
    const delivery = this.writes.then(() => {
      this.assertPrincipalActive()
      return new Promise<void>((resolve, reject) => {
        if (this.socket.readyState !== WebSocket.OPEN) {
          reject(new Error('api gateway: Remote stream socket is closed'))
          return
        }
        this.socket.send(text, (error) => {
          if (error) reject(error)
          else resolve()
        })
      })
    })
    this.writes = delivery.catch(() => undefined)
    return delivery
  }

  private isPrincipalActive(): boolean {
    return !this.lifetime.signal.aborted
      && this.context.invalidated?.aborted !== true
      && (this.context.expiresAt === undefined || this.context.expiresAt > Date.now())
  }

  private assertPrincipalActive(): void {
    if (this.isPrincipalActive()) return
    this.invalidatePrincipal()
    throw new PrincipalInactiveError()
  }

  private invalidatePrincipal(): void {
    if (!this.lifetime.signal.aborted) {
      this.lifetime.abort(new PrincipalInactiveError())
    }
    if (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING) {
      this.socket.close(1008, 'authenticated Principal is no longer active')
    }
  }
}

function remoteStreamHello(context: ConnectionRequestContext, key: Buffer): RemoteStreamHelloMessage {
  if (context.principal === undefined) return { type: 'hello', mode: 'legacy', binding: null }
  if (context.sessionId === undefined) return { type: 'hello', mode: 'authenticated', binding: null }
  const binding = createHmac('sha256', key)
    .update('dsh-remote-stream\0')
    .update(context.sessionId)
    .digest('base64url') as RemoteStreamConnectionBinding
  return { type: 'hello', mode: 'authenticated', binding }
}

class PrincipalInactiveError extends Error {
  constructor() {
    super('api gateway: authenticated Principal is no longer active')
    this.name = 'PrincipalInactiveError'
  }
}

function rawText(data: RawData): string {
  if (Array.isArray(data)) return Buffer.concat(data).toString('utf8')
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString('utf8')
  return Buffer.from(data).toString('utf8')
}

/**
 * Reject an upgrade without transferring socket ownership to ws.
 * @param socket - carrier socket that receives the HTTP rejection.
 * @param status - authentication or browser-trust rejection status.
 */
export function rejectRemoteStreamUpgrade(socket: Duplex, status: 401 | 403 | 503): void {
  const reason = status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : 'Service Unavailable'
  const body = reason.toLowerCase()
  socket.end([
    `HTTP/1.1 ${String(status)} ${reason}`,
    'Connection: close',
    'Content-Type: text/plain; charset=utf-8',
    `Content-Length: ${String(Buffer.byteLength(body))}`,
    '',
    body,
  ].join('\r\n'))
}
