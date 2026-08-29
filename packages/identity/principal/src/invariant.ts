/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-principal`.
 * @module @deepseek-ai/dsh-principal/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-principal'

/** Cordis companion plugin name. */
export const name = 'principal-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: Principal contexts live only in AsyncLocalStorage and
 * validate their expiry and invalidation at each read. The package exposes no
 * independent event stream or mutable projection for a companion to compare.
 */
const install: InvariantInstaller = () => {}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
/* jscpd:ignore-end */
