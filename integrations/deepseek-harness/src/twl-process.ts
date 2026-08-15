import { spawn } from 'node:child_process'
import type { ChildProcessWithoutNullStreams, SpawnOptionsWithoutStdio } from 'node:child_process'
import { ProtocolClient } from './protocol.js'
import type { CapabilityDescriptor, InvokeInput, InvokeResponse } from './protocol.js'

export type SpawnTowel = (
  command: string,
  args: readonly string[],
  options: SpawnOptionsWithoutStdio & { stdio: ['pipe', 'pipe', 'pipe'] },
) => ChildProcessWithoutNullStreams

export interface TwlProcessOptions {
  binary: string
  project: string
  shutdownGraceMs: number
}

/** Owns exactly one versioned Towel stdio session and its complete lifecycle. */
export class TwlProcess {
  readonly #options: TwlProcessOptions
  readonly #spawn: SpawnTowel
  #child: ChildProcessWithoutNullStreams | undefined
  #client: ProtocolClient | undefined
  #ready: Promise<CapabilityDescriptor[]> | undefined
  #disposePromise: Promise<void> | undefined
  #capabilities: CapabilityDescriptor[] | undefined
  #diagnostics = Buffer.alloc(0)

  constructor(options: TwlProcessOptions, spawnTowel: SpawnTowel = spawn as SpawnTowel) {
    this.#options = options
    this.#spawn = spawnTowel
  }

  start(): Promise<CapabilityDescriptor[]> {
    if (this.#disposePromise !== undefined) {
      return Promise.reject(new Error('Towel capability process is disposing'))
    }
    this.#ready ??= this.#start()
    return this.#ready
  }

  async invoke(input: InvokeInput, signal?: AbortSignal): Promise<InvokeResponse> {
    await this.start()
    const client = this.#client
    if (client === undefined) throw new Error('Towel capability process is unavailable')
    if (signal?.aborted === true) {
      await this.dispose()
      throw abortError()
    }
    let aborted = false
    const onAbort = (): void => {
      aborted = true
      void this.dispose()
    }
    signal?.addEventListener('abort', onAbort, { once: true })
    try {
      return await client.invoke(input)
    } catch (error) {
      if (aborted) {
        await this.dispose()
        throw abortError()
      }
      throw error
    } finally {
      signal?.removeEventListener('abort', onAbort)
    }
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return this.#capabilities ?? []
  }

  dispose(): Promise<void> {
    this.#disposePromise ??= this.#dispose()
    return this.#disposePromise
  }

  async #start(): Promise<CapabilityDescriptor[]> {
    const child = this.#spawn(
      this.#options.binary,
      ['capability', 'serve', '--project', this.#options.project, '--stdio'],
      {
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: false,
        windowsHide: true,
        detached: false,
      },
    )
    this.#child = child
    child.stderr.on('data', (chunk: Buffer | string) => {
      const appended = Buffer.concat([this.#diagnostics, Buffer.from(chunk)])
      this.#diagnostics = appended.subarray(Math.max(0, appended.byteLength - 8192))
    })
    const client = new ProtocolClient(child.stdout, child.stdin)
    this.#client = client
    child.once('exit', () => {
      client.close(new Error('Towel capability process exited'))
    })
    child.once('error', () => {
      client.close(new Error('Towel capability process failed to start'))
    })
    try {
      await client.hello()
      const capabilities = await client.list()
      this.#capabilities = capabilities
      return capabilities
    } catch (error) {
      await this.dispose()
      throw new Error('Towel capability process did not become ready', { cause: error })
    }
  }

  async #dispose(): Promise<void> {
    const child = this.#child
    this.#client?.close()
    this.#client = undefined
    this.#capabilities = undefined
    if (child === undefined) return
    if (!child.stdin.destroyed) child.stdin.end()
    if (await waitForExit(child, this.#options.shutdownGraceMs)) return
    child.kill('SIGTERM')
    if (await waitForExit(child, this.#options.shutdownGraceMs)) return
    child.kill('SIGKILL')
    await waitForExit(child, this.#options.shutdownGraceMs)
  }
}

async function waitForExit(child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true
  return new Promise<boolean>((resolve) => {
    let settled = false
    const finish = (exited: boolean): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      child.off('exit', onExit)
      resolve(exited)
    }
    const onExit = (): void => finish(true)
    const timer = setTimeout(() => finish(false), timeoutMs)
    child.once('exit', onExit)
  })
}

function abortError(): Error {
  const error = new Error('Towel capability invocation was cancelled')
  error.name = 'AbortError'
  return error
}
