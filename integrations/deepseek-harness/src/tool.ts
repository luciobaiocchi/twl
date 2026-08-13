import { defineTool } from '@deepseek-ai/dsh-tools'
import type { CapabilityDescriptor } from './protocol.js'
import type { TwlProcess } from './twl-process.js'

export interface ToolResult {
  status: number
  contentType: string
  body: string
  truncated: boolean
}

export function createTowelTool(
  process: Pick<TwlProcess, 'invoke'>,
  capabilities: readonly CapabilityDescriptor[],
  maxModelOutputBytes: number,
) {
  const names = capabilities.map(capability => capability.name)
  const grants = capabilities.length === 0
    ? 'No Towel capabilities are configured.'
    : capabilities.map(capability => {
      const description = capability.description.length === 0
        ? '(no description)'
        : capability.description
      return `${capability.name}: ${description} [${capability.methods.join(', ')}; ${capability.path_prefixes.join(', ')}]`
    }).join('\n')

  return defineTool({
    name: 'twl_request',
    description: 'Invoke one explicitly granted Towel HTTP capability. '
      + 'Towel fixes the destination and applies the protected credential; the credential is not available to you.\n'
      + `Available capabilities:\n${grants}`,
    parameters: {
      capability: {
        type: 'string',
        required: true,
        enum: names,
        description: 'Exact capability name from the available-capabilities list.',
      },
      method: {
        type: 'string',
        required: true,
        description: 'HTTP method allowed by the selected capability.',
      },
      path: {
        type: 'string',
        required: true,
        description: 'Normalized origin-form path. A scheme or host is not accepted.',
      },
      query: {
        type: 'string',
        description: 'Optional query string without a leading question mark.',
      },
      body: {
        type: 'string',
        description: 'Optional UTF-8 request body.',
      },
      content_type: {
        type: 'string',
        description: 'Optional request Content-Type.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          status: { type: 'integer', required: true },
          contentType: { type: 'string', required: true },
          body: { type: 'string', required: true },
          truncated: { type: 'boolean', required: true },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: JSON.stringify(value, null, 2),
      }],
    },
    async execute(args, exec) {
      const response = await process.invoke({
        capability: args.capability,
        method: args.method,
        path: args.path,
        ...(args.query !== undefined ? { query: args.query } : {}),
        ...(args.body !== undefined ? { body: args.body } : {}),
        ...(args.content_type !== undefined ? { content_type: args.content_type } : {}),
      }, exec.signal)
      return renderResponse(response, maxModelOutputBytes)
    },
  })
}

export function renderResponse(
  response: { status: number; content_type: string; body: string },
  maxModelOutputBytes: number,
): ToolResult {
  const bytes = Buffer.from(response.body, 'base64')
  const isText = response.content_type === 'application/json'
    || response.content_type.startsWith('text/')
  if (!isText) {
    return {
      status: response.status,
      contentType: response.content_type,
      body: `[binary response omitted: ${bytes.byteLength} bytes]`,
      truncated: bytes.byteLength > 0,
    }
  }
  const truncated = bytes.byteLength > maxModelOutputBytes
  const selected = bytes.subarray(0, maxModelOutputBytes)
  const body = new TextDecoder('utf-8', { fatal: false }).decode(selected)
  return {
    status: response.status,
    contentType: response.content_type,
    body,
    truncated,
  }
}
