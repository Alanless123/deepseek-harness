/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-principal-oidc`.
 * @module @deepseek-ai/dsh-principal-oidc/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-principal-oidc'

/** Cordis companion plugin name. */
export const name = 'principal-oidc-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: login transactions and Host sessions are private,
 * short-lived maps validated at every protocol operation. The provider has no
 * independent event stream or public mutable projection to compare safely.
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
