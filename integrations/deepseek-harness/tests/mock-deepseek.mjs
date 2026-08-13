#!/usr/bin/env node
import http from 'node:http'

let conversationRequests = 0
let sawToolResult = false

const server = http.createServer(async (request, response) => {
  if (request.method !== 'POST' || request.url !== '/chat/completions') {
    response.writeHead(404).end()
    return
  }
  const chunks = []
  for await (const chunk of request) chunks.push(chunk)
  const body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  const tools = Array.isArray(body.tools) ? body.tools : []
  const messages = Array.isArray(body.messages) ? body.messages : []
  const toolResult = messages.find(message => message.role === 'tool')
  conversationRequests += 1

  response.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
  })
  if (toolResult === undefined) {
    if (!tools.some(tool => tool?.function?.name === 'twl_request')) {
      response.write(`data: ${JSON.stringify({
        choices: [{ delta: { content: 'twl_request was not registered' }, finish_reason: 'stop' }],
      })}\n\n`)
    } else {
      response.write(`data: ${JSON.stringify({
        choices: [{
          delta: {
            tool_calls: [{
              index: 0,
              id: 'call_towel_e2e',
              function: {
                name: 'twl_request',
                arguments: JSON.stringify({
                  capability: 'github-read',
                  method: 'GET',
                  path: '/repos/luciobaiocchi/twl',
                }),
              },
            }],
          },
          finish_reason: 'tool_calls',
        }],
      })}\n\n`)
    }
  } else {
    sawToolResult = typeof toolResult.content === 'string'
      && toolResult.content.includes('/repos/luciobaiocchi/twl')
    response.write(`data: ${JSON.stringify({
      choices: [{
        delta: {
          content: sawToolResult
            ? 'Towel capability result received.'
            : 'Towel capability result was missing.',
        },
        finish_reason: 'stop',
      }],
    })}\n\n`)
  }
  response.write(`data: ${JSON.stringify({
    choices: [],
    usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
  })}\n\n`)
  response.end('data: [DONE]\n\n')
})

server.listen(0, '127.0.0.1', () => {
  const address = server.address()
  if (typeof address === 'object' && address !== null) {
    process.stdout.write(`http://127.0.0.1:${address.port}\n`)
  }
})

const shutdown = () => server.close(() => {
  process.stderr.write(JSON.stringify({ conversationRequests, sawToolResult }) + '\n')
  process.exit(sawToolResult ? 0 : 1)
})
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
