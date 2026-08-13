import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { createTowelTool } from './tool.js'
import { TwlProcess } from './twl-process.js'
import type { CapabilityDescriptor } from './protocol.js'

export const name = 'towel-capabilities'
export const inject = ['tools']

export interface Config {
  project: string
  twlBinary: string
  maxModelOutputBytes: number
  shutdownGraceMs: number
}

export const Config: z<Config> = z.object({
  project: z.string().required().pattern(/^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/),
  twlBinary: z.string().default('twl'),
  maxModelOutputBytes: z.number().default(65_536),
  shutdownGraceMs: z.number().default(1_500),
})

/** Start one private Towel session, discover grants, and register the model tool. */
export async function apply(ctx: Context, config: Config): Promise<void> {
  assertPositiveInteger('maxModelOutputBytes', config.maxModelOutputBytes)
  assertPositiveInteger('shutdownGraceMs', config.shutdownGraceMs)
  if (config.twlBinary.length === 0 || /[\0\r\n]/.test(config.twlBinary)) {
    throw new Error('towel-capabilities: twlBinary must be a non-empty executable path')
  }

  const process = new TwlProcess({
    binary: config.twlBinary,
    project: config.project,
    shutdownGraceMs: config.shutdownGraceMs,
  })
  let ready: Promise<CapabilityDescriptor[]> | undefined
  ctx.effect(() => {
    ready = process.start()
    return () => process.dispose()
  }, 'towel-capabilities.process')

  if (ready === undefined) throw new Error('towel-capabilities: process effect did not start')
  const capabilities = await ready
  ctx.tools.register(createTowelTool(process, capabilities, config.maxModelOutputBytes))
}

function assertPositiveInteger(field: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`towel-capabilities: ${field} must be a positive integer`)
  }
}

export { ProtocolClient, TowelProtocolError } from './protocol.js'
export type { CapabilityDescriptor, InvokeInput, InvokeResponse } from './protocol.js'
export { renderResponse } from './tool.js'
export { TwlProcess } from './twl-process.js'
