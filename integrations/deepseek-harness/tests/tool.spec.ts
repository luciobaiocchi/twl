import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createTowelTool, renderResponse } from '../src/tool.js'
import { TowelProtocolError } from '../src/protocol.js'

test('tool advertises authority names without credential metadata and invokes the adapter', async () => {
  const calls: unknown[] = []
  const process = {
    async invoke(input: unknown) {
      calls.push(input)
      return {
        status: 200,
        content_type: 'application/json',
        body_encoding: 'base64' as const,
        body: Buffer.from('{"private":true}').toString('base64'),
      }
    },
  }
  const tool = createTowelTool(process, [{
    name: 'github-read',
    description: 'Read repository data.',
    methods: ['GET'],
    path_prefixes: ['/repos/'],
    max_response_bytes: 1_048_576,
  }], 65_536)

  assert.match(tool.description, /github-read/)
  assert.doesNotMatch(tool.description, /token|fingerprint|api\.github\.com/i)
  const result = await tool.execute({
    capability: 'github-read',
    method: 'GET',
    path: '/repos/luciobaiocchi/twl',
  }, { signal: new AbortController().signal } as never)
  assert.deepEqual(result, {
    status: 200,
    contentType: 'application/json',
    body: '{"private":true}',
    truncated: false,
  })
  assert.deepEqual(calls, [{
    capability: 'github-read',
    method: 'GET',
    path: '/repos/luciobaiocchi/twl',
  }])
})

test('model-visible text is bounded and binary bodies are omitted', () => {
  const truncated = renderResponse({
    status: 200,
    content_type: 'text/plain',
    body: Buffer.from('123456789').toString('base64'),
  }, 4)
  assert.deepEqual(truncated, {
    status: 200,
    contentType: 'text/plain',
    body: '1234',
    truncated: true,
  })

  const binary = renderResponse({
    status: 200,
    content_type: 'application/octet-stream',
    body: Buffer.from([0, 1, 2]).toString('base64'),
  }, 100)
  assert.equal(binary.body, '[binary response omitted: 3 bytes]')
  assert.equal(binary.truncated, true)
})

test('broker denials retain their stable, secret-free error code', async () => {
  const process = {
    async invoke() {
      throw new TowelProtocolError(
        'METHOD_DENIED',
        'capability does not allow this HTTP method',
      )
    },
  }
  const tool = createTowelTool(process, [{
    name: 'github-read',
    description: 'Read repository data.',
    methods: ['GET'],
    path_prefixes: ['/repos/'],
    max_response_bytes: 1_048_576,
  }], 65_536)

  await assert.rejects(
    tool.execute({
      capability: 'github-read',
      method: 'DELETE',
      path: '/repos/luciobaiocchi/twl',
    }, { signal: new AbortController().signal } as never),
    (error: unknown) => error instanceof TowelProtocolError && error.code === 'METHOD_DENIED',
  )
})
