import "server-only"

import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from "@oslojs/encoding"
import { sha256 } from "@oslojs/crypto/sha2"
import { sql } from "@/lib/db"

interface Session {
  id: string
  userId: string
  expiresAt: Date
}

interface User {
  id: string
}

interface SessionResult {
  session_id: string
  user_id: string
  expires_at: Date
}

export type SessionValidationResult =
  | { session: Session; user: User }
  | { session: null; user: null }

export function generateSessionToken(): string {
  const bytes = new Uint8Array(20)
  crypto.getRandomValues(bytes)
  const token = encodeBase32LowerCaseNoPadding(bytes)
  return token
}

export async function createSession(token: string, userId: string): Promise<Session> {
  const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)))
  const session: Session = {
    id: sessionId,
    userId,
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
  }

  await sql`
    insert into sessions(id, user_id, expires_at) values
    (${session.id}, ${session.userId}, ${session.expiresAt})
  `
  return session
}

export async function validateSessionToken(
  token: string
): Promise<SessionValidationResult> {
  const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)))
  const result = (await sql`
    select 
      sessions.id as session_id,
      sessions.user_id,
      sessions.expires_at
    from sessions
    inner join users on sessions.user_id = users.id
    where sessions.id = ${sessionId}
  `) as SessionResult[]

  if (result.length < 1) {
    return { session: null, user: null }
  }

  const { user_id, session_id, expires_at } = result[0]
  let expiresAt = expires_at

  if (Date.now() >= expires_at.getTime()) {
    await sql`delete from sessions where sessions.id = ${session_id}`
    return { session: null, user: null }
  }
  if (Date.now() >= expires_at.getTime() - 1000 * 60 * 60 * 24 * 15) {
    expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30)
    await sql`update sessions set expires_at = ${expiresAt} where sessions.id = ${session_id}`
  }

  return {
    session: { id: session_id, userId: user_id, expiresAt },
    user: { id: user_id },
  }
}

export async function invalidateSession(sessionId: string) {
  await sql`delete from sessions where sessions.id = ${sessionId}`
}
