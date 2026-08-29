import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import {
  default as PrincipalPlugin,
  PrincipalAuthenticationError,
  PrincipalContextService,
  derivePrincipalId,
  verifiedPrincipal,
} from '../src/index.ts'

function context(subject: string, displayName = subject) {
  const invalidation = new AbortController()
  return {
    principal: verifiedPrincipal({ issuer: 'https://issuer.example/tenant', subject, displayName }),
    expiresAt: Date.now() + 60_000,
    invalidated: invalidation.signal,
    revalidateIntervalMs: 15_000,
  }
}

describe('Principal seam', () => {
  it('loads its request-context service through the default Service plugin export', async () => {
    const root = new Context()
    const fiber = root.plugin(PrincipalPlugin)
    await fiber.await()
    expect(root.get('principals')).toBeInstanceOf(PrincipalContextService)
    await fiber.dispose()
    expect(root.get('principals')).toBeUndefined()
  })

  it('derives identity only from exact issuer and subject', () => {
    const first = verifiedPrincipal({ issuer: 'https://issuer.example/tenant', subject: '42', displayName: 'Alice' })
    const renamed = verifiedPrincipal({ issuer: 'https://issuer.example/tenant', subject: '42', displayName: 'A. User' })
    expect(first.principalId).toBe(renamed.principalId)
    expect(first.principalId).toBe(derivePrincipalId(first.issuer, first.subject))
    expect(derivePrincipalId('https://issuer.example/tenant/', '42')).not.toBe(first.principalId)
    expect(derivePrincipalId(first.issuer, '43')).not.toBe(first.principalId)
  })

  it('isolates concurrent request contexts and fails closed without one', async () => {
    const root = new Context()
    const principals = new PrincipalContextService(root)
    expect(() => principals.require()).toThrow(PrincipalAuthenticationError)
    const seen = await Promise.all([
      principals.run(context('alice'), async () => {
        await new Promise(resolve => setTimeout(resolve, 5))
        return principals.require().principal.subject
      }),
      principals.run(context('bob'), async () => {
        await Promise.resolve()
        return principals.require().principal.subject
      }),
    ])
    expect(seen).toEqual(['alice', 'bob'])
    expect(principals.current()).toBeUndefined()
  })

  it('rejects expired and invalidated contexts', () => {
    const root = new Context()
    const principals = new PrincipalContextService(root)
    const invalidation = new AbortController()
    const expired = { ...context('expired'), expiresAt: Date.now() - 1 }
    expect(() => { principals.run(expired, () => undefined) }).toThrow('no longer active')
    const revoked = { ...context('revoked'), invalidated: invalidation.signal }
    invalidation.abort()
    expect(() => { principals.run(revoked, () => undefined) }).toThrow('no longer active')
    expect(() => { principals.run({ ...context('invalid-cadence'), revalidateIntervalMs: 0 }, () => undefined) })
      .toThrow('no longer active')
  })
})
