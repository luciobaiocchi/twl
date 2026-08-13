import type { Readable, Writable } from 'node:stream'

const PROTOCOL_VERSION = 1
const MAX_FRAME_BYTES = 32 * 1024 * 1024

export interface CapabilityDescriptor {
  name: string
  description: string
  methods: string[]
  path_prefixes: string[]
  max_response_bytes: number
}

export interface InvokeInput {
  capability: string
  method: string
  path: string
  query?: string
  body?: string
  content_type?: string
}

export interface InvokeResponse {
  status: number
  content_type: string
  body_encoding: 'base64'
  body: string
}

interface Pending {
  resolve(value: Record<string, unknown>): void
  reject(error: Error): void
}

export class TowelProtocolError extends Error {
  constructor(readonly code: string, message: string) {
    super(message)
    this.name = 'TowelProtocolError'
  }
}

/** Bounded NDJSON protocol client. It never logs request or response frames. */
export class ProtocolClient {
  readonly #readable: Readable
  readonly #writable: Writable
  readonly #pending = new Map<string, Pending>()
  #hello: Pending | undefined
  #buffer = Buffer.alloc(0)
  #nextId = 1
  #closedError: Error | undefined

  constructor(readable: Readable, writable: Writable) {
    this.#readable = readable
    this.#writable = writable
    readable.on('data', (chunk: Buffer | string) => this.#onData(Buffer.from(chunk)))
    readable.on('end', () => this.close(new Error('Towel capability protocol closed')))
    readable.on('error', () => this.close(new Error('Towel capability protocol read failed')))
    writable.on('error', () => this.close(new Error('Towel capability protocol write failed')))
  }

  async hello(): Promise<void> {
    if (this.#hello !== undefined) throw new Error('Towel capability handshake already pending')
    const response = await new Promise<Record<string, unknown>>((resolve, reject) => {
      this.#hello = { resolve, reject }
      void this.#write({ op: 'hello', protocol: PROTOCOL_VERSION }).catch((error: unknown) => {
        this.#hello = undefined
        reject(asError(error))
      })
    })
    if (response.ok !== true || response.protocol !== PROTOCOL_VERSION || response.server !== 'twl') {
      throw new Error('Towel capability handshake returned an invalid response')
    }
  }

  async list(): Promise<CapabilityDescriptor[]> {
    const response = await this.#request({ op: 'list' })
    if (!Array.isArray(response.capabilities)) {
      throw new Error('Towel capability list returned an invalid response')
    }
    return response.capabilities.map(parseCapability)
  }

  async invoke(input: InvokeInput): Promise<InvokeResponse> {
    const response = await this.#request({ op: 'invoke', ...input })
    if (
      typeof response.status !== 'number'
      || !Number.isInteger(response.status)
      || typeof response.content_type !== 'string'
      || response.body_encoding !== 'base64'
      || typeof response.body !== 'string'
    ) {
      throw new Error('Towel capability invocation returned an invalid response')
    }
    return {
      status: response.status,
      content_type: response.content_type,
      body_encoding: 'base64',
      body: response.body,
    }
  }

  close(error = new Error('Towel capability client disposed')): void {
    if (this.#closedError !== undefined) return
    this.#closedError = error
    this.#hello?.reject(error)
    this.#hello = undefined
    for (const pending of this.#pending.values()) pending.reject(error)
    this.#pending.clear()
    this.#readable.removeAllListeners('data')
  }

  async #request(fields: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.#closedError !== undefined) throw this.#closedError
    const id = String(this.#nextId++)
    return new Promise<Record<string, unknown>>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject })
      void this.#write({ id, ...fields }).catch((error: unknown) => {
        this.#pending.delete(id)
        reject(asError(error))
      })
    })
  }

  async #write(frame: Record<string, unknown>): Promise<void> {
    if (this.#closedError !== undefined) throw this.#closedError
    const encoded = Buffer.from(`${JSON.stringify(frame)}\n`)
    if (encoded.byteLength > MAX_FRAME_BYTES) {
      throw new Error('Towel capability request exceeds the adapter frame limit')
    }
    if (this.#writable.write(encoded)) return
    await new Promise<void>((resolve, reject) => {
      const onDrain = (): void => {
        cleanup()
        resolve()
      }
      const onError = (): void => {
        cleanup()
        reject(new Error('Towel capability protocol write failed'))
      }
      const cleanup = (): void => {
        this.#writable.off('drain', onDrain)
        this.#writable.off('error', onError)
      }
      this.#writable.once('drain', onDrain)
      this.#writable.once('error', onError)
    })
  }

  #onData(chunk: Buffer): void {
    if (this.#closedError !== undefined) return
    this.#buffer = Buffer.concat([this.#buffer, chunk])
    if (this.#buffer.byteLength > MAX_FRAME_BYTES && !this.#buffer.includes(0x0a)) {
      this.close(new Error('Towel capability response exceeds the adapter frame limit'))
      return
    }
    while (true) {
      const newline = this.#buffer.indexOf(0x0a)
      if (newline < 0) return
      if (newline > MAX_FRAME_BYTES) {
        this.close(new Error('Towel capability response exceeds the adapter frame limit'))
        return
      }
      const line = this.#buffer.subarray(0, newline)
      this.#buffer = this.#buffer.subarray(newline + 1)
      this.#onLine(line)
      if (this.#closedError !== undefined) return
    }
  }

  #onLine(line: Buffer): void {
    let frame: unknown
    try {
      frame = JSON.parse(line.toString('utf8'))
    } catch {
      this.close(new Error('Towel capability protocol returned malformed JSON'))
      return
    }
    if (!isRecord(frame)) {
      this.close(new Error('Towel capability protocol returned a malformed response'))
      return
    }
    const id = typeof frame.id === 'string' ? frame.id : undefined
    const pending = id === undefined ? this.#hello : this.#pending.get(id)
    if (pending === undefined) {
      this.close(new Error('Towel capability protocol returned an unexpected response'))
      return
    }
    if (id === undefined) this.#hello = undefined
    else this.#pending.delete(id)
    if (frame.ok !== true) {
      const error = isRecord(frame.error) ? frame.error : {}
      pending.reject(new TowelProtocolError(
        typeof error.code === 'string' ? error.code : 'INVALID_RESPONSE',
        typeof error.message === 'string' ? error.message : 'Towel capability request failed',
      ))
      return
    }
    pending.resolve(frame)
  }
}

function parseCapability(value: unknown): CapabilityDescriptor {
  if (
    !isRecord(value)
    || typeof value.name !== 'string'
    || typeof value.description !== 'string'
    || !isStringArray(value.methods)
    || !isStringArray(value.path_prefixes)
    || typeof value.max_response_bytes !== 'number'
    || !Number.isSafeInteger(value.max_response_bytes)
  ) {
    throw new Error('Towel capability list contained an invalid descriptor')
  }
  return {
    name: value.name,
    description: value.description,
    methods: value.methods,
    path_prefixes: value.path_prefixes,
    max_response_bytes: value.max_response_bytes,
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(item => typeof item === 'string')
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error('Towel capability protocol failed')
}
