import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { test } from 'node:test'
import type { ChildProcessWithoutNullStreams } from 'node:child_process'
import { TwlProcess } from '../src/twl-process.js'
import type { SpawnTowel } from '../src/twl-process.js'

test('process owns private pipes, performs discovery, and exits on disposal', async () => {
  const child = new FakeChild(true)
  const calls: unknown[][] = []
  const spawn: SpawnTowel = (command, args, options) => {
    calls.push([command, args, options])
    serveHandshake(child)
    return child as unknown as ChildProcessWithoutNullStreams
  }
  const process = new TwlProcess({
    binary: '/trusted/bin/twl',
    project: 'dsh-demo',
    shutdownGraceMs: 20,
  }, spawn)

  const capabilities = await process.start()
  assert.equal(capabilities[0]?.name, 'github-read')
  await process.dispose()

  const [command, args, options] = calls[0] ?? []
  assert.equal(command, '/trusted/bin/twl')
  assert.deepEqual(args, ['capability', 'serve', '--project', 'dsh-demo', '--stdio'])
  assert.deepEqual((options as { stdio: string[] }).stdio, ['pipe', 'pipe', 'pipe'])
  assert.equal((options as { shell: boolean }).shell, false)
  assert.equal(JSON.stringify(calls).includes('credential-canary'), false)
  assert.equal(child.exited, true)
  assert.deepEqual(child.kills, [])
})

test('disposal rejects an outstanding call and escalates to SIGTERM when EOF is ignored', async () => {
  const child = new FakeChild(false)
  const spawn: SpawnTowel = () => {
    serveHandshake(child, true)
    return child as unknown as ChildProcessWithoutNullStreams
  }
  const process = new TwlProcess({ binary: 'twl', project: 'demo', shutdownGraceMs: 5 }, spawn)
  await process.start()
  const pending = process.invoke({ capability: 'github-read', method: 'GET', path: '/repos/a' })
  const rejected = assert.rejects(pending, /disposed|exited|closed|unavailable/)
  await process.dispose()
  await rejected
  assert.deepEqual(child.kills, ['SIGTERM'])
  assert.equal(child.exited, true)
})

test('unexpected process exit rejects an outstanding invocation', async () => {
  const child = new FakeChild(false)
  const spawn: SpawnTowel = () => {
    serveHandshake(child, true)
    return child as unknown as ChildProcessWithoutNullStreams
  }
  const process = new TwlProcess({ binary: 'twl', project: 'demo', shutdownGraceMs: 5 }, spawn)
  await process.start()

  const pending = process.invoke({ capability: 'github-read', method: 'GET', path: '/repos/a' })
  child.exit(1, null)

  await assert.rejects(pending, /exited/)
  await process.dispose()
})

test('startup failure closes the process and rejects discovery', async () => {
  const child = new FakeChild(true)
  const spawn: SpawnTowel = () => {
    queueMicrotask(() => child.emit('error', new Error('executable unavailable')))
    return child as unknown as ChildProcessWithoutNullStreams
  }
  const process = new TwlProcess({ binary: 'missing-twl', project: 'demo', shutdownGraceMs: 5 }, spawn)

  await assert.rejects(process.start(), /did not become ready/)
  assert.equal(child.exited, true)
})

class FakeChild extends EventEmitter {
  readonly stdin = new PassThrough()
  readonly stdout = new PassThrough()
  readonly stderr = new PassThrough()
  exitCode: number | null = null
  signalCode: NodeJS.Signals | null = null
  readonly kills: NodeJS.Signals[] = []
  exited = false

  constructor(exitOnEof: boolean) {
    super()
    if (exitOnEof) this.stdin.once('finish', () => this.exit(0, null))
  }

  kill(signal: NodeJS.Signals = 'SIGTERM'): boolean {
    this.kills.push(signal)
    this.exit(null, signal)
    return true
  }

  exit(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.exited) return
    this.exited = true
    this.exitCode = code
    this.signalCode = signal
    this.emit('exit', code, signal)
  }
}

function serveHandshake(child: FakeChild, ignoreInvoke = false): void {
  let buffer = ''
  child.stdin.on('data', (chunk: Buffer | string) => {
    buffer += chunk.toString()
    while (true) {
      const newline = buffer.indexOf('\n')
      if (newline < 0) return
      const request = JSON.parse(buffer.slice(0, newline)) as Record<string, unknown>
      buffer = buffer.slice(newline + 1)
      if (request.op === 'hello') {
        child.stdout.write('{"ok":true,"protocol":1,"server":"twl","capability_count":1}\n')
      } else if (request.op === 'list') {
        child.stdout.write(`${JSON.stringify({
          id: request.id,
          ok: true,
          capabilities: [{
            name: 'github-read',
            description: 'Read repository data.',
            methods: ['GET'],
            path_prefixes: ['/repos/'],
            max_response_bytes: 1_048_576,
          }],
        })}\n`)
      } else if (!ignoreInvoke) {
        child.stdout.write(`${JSON.stringify({
          id: request.id,
          ok: true,
          status: 200,
          content_type: 'application/json',
          body_encoding: 'base64',
          body: Buffer.from('{}').toString('base64'),
        })}\n`)
      }
    }
  })
}
