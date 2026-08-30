/** Browser owner for the Gateway multiplexed Remote stream socket. */

import {
  parseRemoteStreamServerMessage,
  REMOTE_STREAM_MUX_PATH,
  type RemoteStreamClientMessage,
  type RemoteStreamHelloMessage,
  type RemoteStreamServerMessage,
} from '../stream-protocol.ts'
import { randomUUID } from '@deepseek-ai/dsh-util-crypto'

const INTERNAL_BASE = 'http://dsh.internal'
const RECONNECT_BASE_MS = 500
const RECONNECT_FACTOR = 2
const RECONNECT_MAX_MS = 10_000
const AUTHENTICATED_RESUME_WINDOW_MS = 30_000
const HOST_HELLO_WINDOW_MS = 30_000

/** One Host-reported Remote stream failure. */
export class RemoteStreamError extends Error {
  /** Stable carrier or Gateway error category. */
  readonly code: string
  /** Host-provided structured failure context. */
  readonly details: object

  /**
   * @param code - stable Gateway or business error category.
   * @param message - Host-provided failure description.
   * @param details - Host-provided structured failure context.
   */
  constructor(code: string, message: string, details: object) {
    super(message)
    this.name = 'RemoteStreamError'
    this.code = code
    this.details = details
  }
}

/** Physical Remote stream socket failure that may be retried by a domain transport. */
export class RemoteStreamCarrierError extends Error {
  /**
   * @param message - physical carrier failure description.
   * @param options - optional causal error.
   */
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'RemoteStreamCarrierError'
  }
}

interface SocketWaiter {
  readonly expectedBinding?: RemoteStreamHelloMessage
  resolve(socket: WebSocket): void
  reject(error: unknown): void
}

type RemoteStreamLogicalMessage = Exclude<RemoteStreamServerMessage, RemoteStreamHelloMessage>

/** Keep one physical WebSocket and share it among independently cancellable Remote streams. */
export class RemoteStreamMuxClient {
  private socket: WebSocket | undefined
  private cancelCandidate: ((error: Error, code?: number, reason?: string) => void) | undefined
  private keepAlive: Promise<void> | undefined
  private keepAliveAbort: AbortController | undefined
  private readonly streams = new Map<string, StreamInbox>()
  private readonly waiters = new Set<SocketWaiter>()
  private binding: RemoteStreamHelloMessage | undefined
  private pendingGenerationFailure: RemoteStreamCarrierError | undefined
  private authenticatedResumeTimer: ReturnType<typeof setTimeout> | undefined
  private running = false
  private disposed = false

  /** Start the persistent physical connection; repeated calls are inert. */
  start(): void {
    if (this.running || this.disposed) return
    this.running = true
    this.maintain()
  }

  /**
   * Open one logical stream on the persistent physical connection.
   * @param endpoint - Typert Remote stream endpoint.
   * @param payload - endpoint request encoded on the wire.
   * @param signal - cancellation for this logical stream.
   * @returns Host items until completion, cancellation, or failure.
   */
  async *open(
    endpoint: string,
    payload: unknown,
    signal: AbortSignal,
  ): AsyncGenerator {
    this.start()
    signal.throwIfAborted()
    const streamId = randomUUID()
    const inbox = new StreamInbox()
    let carrier: WebSocket | undefined
    let opened = false
    let terminal = false
    const abort = (): void => { inbox.fail(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    try {
      const socket = await this.waitForSocket(signal)
      signal.throwIfAborted()
      carrier = socket
      this.streams.set(streamId, inbox)
      this.send(socket, { type: 'open', streamId, endpoint, payload })
      opened = true
      while (true) {
        const frame = await inbox.next()
        signal.throwIfAborted()
        if (frame.type === 'item') {
          yield frame.value
          continue
        }
        terminal = true
        if (frame.type === 'error') {
          throw new RemoteStreamError(frame.error.code, frame.error.message, frame.error.details)
        }
        return
      }
    } finally {
      signal.removeEventListener('abort', abort)
      this.streams.delete(streamId)
      if (opened && !terminal && carrier?.readyState === WebSocket.OPEN) {
        this.send(carrier, { type: 'cancel', streamId })
      }
    }
  }

  /**
   * Permanently stop reconnecting, close the physical socket, and fail every active logical stream.
   * @returns once the background connection loop has stopped.
   */
  async close(): Promise<void> {
    if (!this.disposed) {
      this.disposed = true
      this.running = false
      const error = new Error('api gateway: Remote stream client disposed')
      this.keepAliveAbort?.abort(error)
      this.keepAliveAbort = undefined
      this.clearAuthenticatedResumeTimer()
      this.pendingGenerationFailure = undefined
      this.failAll(error)
      for (const waiter of [...this.waiters]) waiter.reject(error)
      this.cancelCandidate?.(error)
      const socket = this.socket
      this.socket = undefined
      socket?.close(1000, 'disposed')
    }
    await this.keepAlive
  }

  private connect(): Promise<WebSocket> {
    const socket = new WebSocket(remoteStreamUrl())
    const connecting = new Promise<WebSocket>((resolve, reject) => {
      let settled = false
      let physicalOpen = false
      const helloTimer = setTimeout(() => {
        rejectCandidate(
          new RemoteStreamCarrierError('api gateway: Remote stream Host hello timed out'),
          4002,
          'Remote stream Host hello timed out',
        )
      }, HOST_HELLO_WINDOW_MS)
      const rejectCandidate = (error: Error, code?: number, reason?: string): void => {
        if (settled) return
        settled = true
        clearTimeout(helloTimer)
        socket.removeEventListener('open', opened)
        socket.removeEventListener('error', failed)
        socket.removeEventListener('message', received)
        socket.removeEventListener('close', closed)
        this.cancelCandidate = undefined
        socket.close(code, reason)
        reject(error)
      }
      const accepted = (hello: RemoteStreamHelloMessage): void => {
        if (settled) return
        settled = true
        clearTimeout(helloTimer)
        this.cancelCandidate = undefined
        this.socket = socket
        this.acceptBinding(hello)
        for (const waiter of [...this.waiters]) {
          if (waiter.expectedBinding !== undefined && !canResumeRemoteStreams(waiter.expectedBinding, hello)) {
            waiter.reject(remoteStreamBindingError())
          } else {
            waiter.resolve(socket)
          }
        }
        resolve(socket)
      }
      const opened = (): void => { physicalOpen = true }
      const failed = (): void => {
        if (!settled) {
          rejectCandidate(new RemoteStreamCarrierError(
            physicalOpen
              ? 'api gateway: Remote stream WebSocket failed before Host hello'
              : 'api gateway: Remote stream WebSocket failed to open',
          ))
          return
        }
        const error = new RemoteStreamCarrierError('api gateway: Remote stream WebSocket failed')
        this.lost(socket, error)
        socket.close()
      }
      const closed = (event: CloseEvent): void => {
        const error = remoteStreamCloseError(event)
        if (!settled) {
          if (error instanceof RemoteStreamError) {
            this.failPendingGeneration(error)
            this.failWaiters(error)
          }
          rejectCandidate(error)
          return
        }
        this.lost(socket, error)
      }
      const received = (event: MessageEvent): void => {
        if (settled) {
          this.receive(socket, event.data)
          return
        }
        try {
          const message = decodeRemoteStreamServerMessage(event.data)
          if (message.type !== 'hello') {
            throw new Error('api gateway: Remote stream Host hello must be the first frame')
          }
          accepted(message)
        } catch (cause) {
          this.failPendingGeneration(remoteStreamBindingError())
          rejectCandidate(
            new RemoteStreamCarrierError('api gateway: invalid Remote stream Host hello', { cause }),
            4002,
            'invalid Remote stream Host hello',
          )
        }
      }
      this.cancelCandidate = rejectCandidate
      socket.addEventListener('open', opened, { once: true })
      socket.addEventListener('error', failed, { once: true })
      socket.addEventListener('message', received)
      socket.addEventListener('close', closed, { once: true })
    })
    return connecting
  }

  private waitForSocket(signal: AbortSignal): Promise<WebSocket> {
    signal.throwIfAborted()
    if (this.socket?.readyState === WebSocket.OPEN) return Promise.resolve(this.socket)
    if (this.disposed) return Promise.reject(new Error('api gateway: Remote stream client disposed'))
    this.start()
    return new Promise((resolve, reject) => {
      const expectedBinding = this.binding
      const aborted = (): void => { waiter.reject(signal.reason) }
      const cleanup = (): void => {
        clearTimeout(timeout)
        this.waiters.delete(waiter)
        signal.removeEventListener('abort', aborted)
      }
      const waiter: SocketWaiter = {
        ...(expectedBinding === undefined ? {} : { expectedBinding }),
        resolve: (socket) => {
          cleanup()
          resolve(socket)
        },
        reject: (error) => {
          cleanup()
          // AbortSignal.reason belongs to the caller and may intentionally be a non-Error sentinel.
          // oxlint-disable-next-line typescript/prefer-promise-reject-errors
          reject(error)
        },
      }
      const timeout = setTimeout(
        () => { waiter.reject(socketWaitTimeoutError(expectedBinding)) },
        expectedBinding?.mode === 'authenticated'
          ? AUTHENTICATED_RESUME_WINDOW_MS
          : HOST_HELLO_WINDOW_MS,
      )
      this.waiters.add(waiter)
      signal.addEventListener('abort', aborted, { once: true })
    })
  }

  private receive(socket: WebSocket, data: unknown): void {
    if (socket !== this.socket) return
    try {
      const frame = decodeRemoteStreamServerMessage(data)
      if (frame.type === 'hello') throw new Error('api gateway: duplicate Remote stream Host hello')
      this.streams.get(frame.streamId)?.push(frame)
    } catch (error) {
      const failure = new RemoteStreamCarrierError('api gateway: invalid Remote stream frame', { cause: error })
      this.lost(socket, failure)
      socket.close(4002, 'invalid Remote stream frame')
    }
  }

  private lost(
    socket: WebSocket,
    error: Error,
  ): void {
    if (this.socket !== socket) return
    this.socket = undefined
    if (error instanceof RemoteStreamCarrierError) this.deferGenerationFailure(error)
    else this.failPendingGeneration(error)
    this.maintain(error)
  }

  private maintain(previousFailure?: Error): void {
    if (!this.running) return
    if (this.keepAlive !== undefined) {
      void this.keepAlive.then(() => { this.maintain(previousFailure) })
      return
    }
    const abort = new AbortController()
    this.keepAliveAbort = abort
    const task = this.reconnect(abort.signal, previousFailure)
    this.keepAlive = task
    void task.then(() => {
      this.keepAlive = undefined
      this.keepAliveAbort = undefined
    })
  }

  private async reconnect(signal: AbortSignal, previousFailure?: Error): Promise<void> {
    let attempt = 0
    let failure = previousFailure
    while (this.isRunning(signal) && this.socket?.readyState !== WebSocket.OPEN) {
      if (failure !== undefined) {
        attempt += 1
        console.warn(`[api-gateway] Remote stream connection unavailable, retry #${String(attempt)}`, failure)
        await sleep(backoffDelay(attempt), signal)
        if (!this.isRunning(signal)) return
      }
      try {
        await this.connect()
        return
      } catch (error) {
        if (!this.isRunning(signal)) return
        failure = error as Error
      }
    }
  }

  private isRunning(signal: AbortSignal): boolean {
    return this.running && !signal.aborted
  }

  private failAll(error: unknown): void {
    for (const stream of this.streams.values()) stream.fail(error)
  }

  private failWaiters(error: unknown): void {
    for (const waiter of [...this.waiters]) waiter.reject(error)
  }

  private failAuthenticatedWaiters(error: unknown): void {
    for (const waiter of [...this.waiters]) {
      if (waiter.expectedBinding !== undefined) waiter.reject(error)
    }
  }

  private acceptBinding(binding: RemoteStreamHelloMessage): void {
    const previous = this.binding
    const failure = this.pendingGenerationFailure
    this.binding = binding
    this.clearAuthenticatedResumeTimer()
    this.pendingGenerationFailure = undefined
    if (failure === undefined) return
    this.failAll(previous !== undefined && canResumeRemoteStreams(previous, binding)
      ? failure
      : remoteStreamBindingError())
  }

  private failPendingGeneration(error: Error): void {
    this.clearAuthenticatedResumeTimer()
    this.pendingGenerationFailure = undefined
    this.failAll(error)
  }

  private deferGenerationFailure(error: RemoteStreamCarrierError): void {
    this.pendingGenerationFailure = error
    this.clearAuthenticatedResumeTimer()
    if (this.binding?.mode !== 'authenticated') {
      this.failPendingGeneration(error)
      return
    }
    if (this.binding.binding === null) {
      this.failPendingGeneration(remoteStreamBindingError())
      return
    }
    this.authenticatedResumeTimer = setTimeout(() => {
      this.authenticatedResumeTimer = undefined
      if (this.pendingGenerationFailure !== undefined) {
        const policy = remoteStreamResumeTimeoutError()
        this.failPendingGeneration(policy)
        this.failAuthenticatedWaiters(policy)
        this.cancelCandidate?.(policy, 4003, 'authenticated Remote stream resume timed out')
      }
    }, AUTHENTICATED_RESUME_WINDOW_MS)
  }

  private clearAuthenticatedResumeTimer(): void {
    clearTimeout(this.authenticatedResumeTimer)
    this.authenticatedResumeTimer = undefined
  }

  private send(socket: WebSocket, message: RemoteStreamClientMessage): void {
    socket.send(JSON.stringify(message))
  }
}

function remoteStreamCloseError(event: CloseEvent): Error {
  if (event.code === 1008) {
    return new RemoteStreamError(
      'remote-stream-policy',
      'api gateway: Remote stream policy rejected the connection',
      {},
    )
  }
  return new RemoteStreamCarrierError('api gateway: Remote stream WebSocket closed')
}

function backoffDelay(attempt: number): number {
  const cap = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * RECONNECT_FACTOR ** Math.max(0, attempt - 1))
  return cap / 2 + Math.random() * (cap / 2)
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms)
    signal.addEventListener('abort', done, { once: true })
    function done(): void {
      clearTimeout(timer)
      signal.removeEventListener('abort', done)
      resolve()
    }
  })
}

class StreamInbox {
  private readonly frames: RemoteStreamLogicalMessage[] = []
  private wake: (() => void) | undefined
  private failure: Error | undefined

  push(frame: RemoteStreamLogicalMessage): void {
    if (this.failure !== undefined) return
    this.frames.push(frame)
    this.wake?.()
    this.wake = undefined
  }

  fail(error: unknown): void {
    if (this.failure !== undefined) return
    this.failure = error instanceof Error ? error : new Error(String(error), { cause: error })
    this.frames.length = 0
    this.wake?.()
    this.wake = undefined
  }

  async next(): Promise<RemoteStreamLogicalMessage> {
    while (this.frames.length === 0) {
      if (this.failure !== undefined) throw this.failure
      await new Promise<void>((resolve) => { this.wake = resolve })
    }
    return this.frames.shift() as RemoteStreamLogicalMessage
  }
}

function decodeRemoteStreamServerMessage(data: unknown): RemoteStreamServerMessage {
  if (typeof data !== 'string') throw new Error('api gateway: Remote stream WebSocket requires text messages')
  return parseRemoteStreamServerMessage(data)
}

function canResumeRemoteStreams(
  previous: RemoteStreamHelloMessage,
  current: RemoteStreamHelloMessage,
): boolean {
  if (previous.mode === 'legacy') return current.mode === 'legacy'
  return current.mode === 'authenticated'
    && previous.binding !== null
    && previous.binding === current.binding
}

function remoteStreamBindingError(): RemoteStreamError {
  return new RemoteStreamError(
    'remote-stream-policy',
    'api gateway: Remote stream authentication changed while reconnecting',
    {},
  )
}

function remoteStreamResumeTimeoutError(): RemoteStreamError {
  return new RemoteStreamError(
    'remote-stream-policy',
    'api gateway: Remote stream authentication could not be confirmed while reconnecting',
    { reason: 'authenticated-resume-window-expired' },
  )
}

function socketWaitTimeoutError(binding: RemoteStreamHelloMessage | undefined): Error {
  if (binding?.mode === 'authenticated') return remoteStreamResumeTimeoutError()
  return new RemoteStreamCarrierError(
    binding === undefined
      ? 'api gateway: Remote stream connection could not be established within the Host hello window'
      : 'api gateway: legacy Remote stream connection could not be restored within the Host hello window',
  )
}

function remoteStreamUrl(): string {
  const location = (globalThis as { location?: { origin?: string } }).location
  const base = location?.origin !== undefined && location.origin !== 'null' ? location.origin : INTERNAL_BASE
  const url = new URL(REMOTE_STREAM_MUX_PATH, base)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  return url.href
}
