import assert from 'node:assert/strict'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import { apply } from '../src/index.js'

test('plugin starts Towel inside an effect, discovers capabilities, and registers twl_request', async () => {
  const disposers: Array<() => void | Promise<void>> = []
  let registered: ToolDefinition | undefined
  const ctx = {
    effect(acquire: () => () => void | Promise<void>) {
      disposers.push(acquire())
    },
    tools: {
      register(tool: ToolDefinition) {
        registered = tool
      },
    },
  }
  await apply(ctx as never, {
    project: 'demo',
    twlBinary: fileURLToPath(new URL('fake-twl', import.meta.url).href.replace('/lib/tests/', '/tests/')),
    maxModelOutputBytes: 65_536,
    shutdownGraceMs: 100,
  })

  assert.equal(registered?.name, 'twl_request')
  assert.match(registered?.description ?? '', /github-read/)
  const result = await registered?.execute({
    capability: 'github-read',
    method: 'GET',
    path: '/repos/luciobaiocchi/twl',
  }, { signal: new AbortController().signal } as never)
  assert.deepEqual(result, {
    status: 200,
    contentType: 'application/json',
    body: '{"adapter":true}',
    truncated: false,
  })

  for (const dispose of disposers.reverse()) await dispose()
})
