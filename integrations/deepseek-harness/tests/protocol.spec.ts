import assert from 'node:assert/strict'
import { test } from 'node:test'
import { PassThrough } from 'node:stream'
import { ProtocolClient, TowelProtocolError } from '../src/protocol.js'

test('handshake, capability discovery, and invocation use correlated NDJSON frames', async () => {
  const serverOutput = new PassThrough()
  const serverInput = new PassThrough()
  const client = new ProtocolClient(serverOutput, serverInput)
  const requests: Array<Record<string, unknown>> = []
  receiveLines(serverInput, (request) => {
    requests.push(request)
    if (request.op === 'hello') {
      send(serverOutput, { ok: true, protocol: 1, server: 'twl', capability_count: 1 })
    } else if (request.op === 'list') {
      send(serverOutput, {
        id: request.id,
        ok: true,
        capabilities: [{
          name: 'github-read',
          description: 'Read repository data.',
          methods: ['GET'],
          path_prefixes: ['/repos/'],
          max_response_bytes: 1_048_576,
        }],
      })
    } else {
      send(serverOutput, {
        id: request.id,
        ok: true,
        status: 200,
        content_type: 'application/json',
        body_encoding: 'base64',
        body: Buffer.from('{"ok":true}').toString('base64'),
      })
    }
  })

  await client.hello()
  const capabilities = await client.list()
  const response = await client.invoke({
    capability: 'github-read',
    method: 'GET',
    path: '/repos/luciobaiocchi/twl',
  })

  assert.equal(capabilities[0]?.name, 'github-read')
  assert.equal(response.status, 200)
  assert.deepEqual(requests.map(request => request.op), ['hello', 'list', 'invoke'])
  assert.equal(Object.hasOwn(requests[2] ?? {}, 'host'), false)
  client.close()
})

test('stable broker denial is surfaced without protocol frame contents', async () => {
  const serverOutput = new PassThrough()
  const serverInput = new PassThrough()
  const client = new ProtocolClient(serverOutput, serverInput)
  receiveLines(serverInput, (request) => {
    if (request.op === 'hello') {
      send(serverOutput, { ok: true, protocol: 1, server: 'twl', capability_count: 0 })
    } else {
      send(serverOutput, {
        id: request.id,
        ok: false,
        error: { code: 'METHOD_DENIED', message: 'capability does not allow this HTTP method' },
      })
    }
  })
  await client.hello()
  await assert.rejects(
    client.list(),
    (error: unknown) => error instanceof TowelProtocolError && error.code === 'METHOD_DENIED',
  )
  client.close()
})

test('malformed server output rejects pending work deterministically', async () => {
  const serverOutput = new PassThrough()
  const serverInput = new PassThrough()
  const client = new ProtocolClient(serverOutput, serverInput)
  const handshake = client.hello()
  serverOutput.write('not-json\n')
  await assert.rejects(handshake, /malformed JSON/)
})

function receiveLines(
  stream: PassThrough,
  receive: (request: Record<string, unknown>) => void,
): void {
  let buffer = ''
  stream.on('data', (chunk: Buffer | string) => {
    buffer += chunk.toString()
    while (true) {
      const newline = buffer.indexOf('\n')
      if (newline < 0) return
      const line = buffer.slice(0, newline)
      buffer = buffer.slice(newline + 1)
      receive(JSON.parse(line) as Record<string, unknown>)
    }
  })
}

function send(stream: PassThrough, value: Record<string, unknown>): void {
  stream.write(`${JSON.stringify(value)}\n`)
}
