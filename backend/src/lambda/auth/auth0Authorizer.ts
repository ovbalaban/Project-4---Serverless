import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify, decode } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import Axios from 'axios'
import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
// Done
const jwksUrl = 'https://dev-i3uc6oxs.us.auth0.com/.well-known/jwks.json'

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  const jwt: Jwt = decode(token, { complete: true }) as Jwt

  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return undefined
  const jwks = await Axios(jwksUrl)

  const jwksData = jwks.data

  const usedKey = jwksData['keys'].find((key) => key.kid === jwt.header.kid)

  if (!usedKey) {
    throw new Error('Invalid token')
  }

  const cert = `-----BEGIN CERTIFICATE-----
  MIIDDTCCAfWgAwIBAgIJefRwywQfF8U/MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
  BAMTGWRldi1pM3VjNm94cy51cy5hdXRoMC5jb20wHhcNMjIwNzE0MTg0NzA0WhcN
  MzYwMzIyMTg0NzA0WjAkMSIwIAYDVQQDExlkZXYtaTN1YzZveHMudXMuYXV0aDAu
  Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxAonUuahxXqwuDq1
  JND2xzOTGDUV/zI2ZglLEsflX/4ew8Z+kB62wDDvpNJuB6R8kmhhHKuY8KkIdAqQ
  23q/zoQ6j/8cIvIIGFuAOooAnJ0l2S8knGanTdLW7Z5v2GF2RRrmt37Lhzasi4gY
  wGySU4uN9QnzsCIlHN8g88HJXbIOIFmoZoMgPTKDEdSijgwRa7xN3Bs71VC9gAw+
  RF3+mAxcYjiL3Hj5PHMKWeB1garqy24iAZfpVeF1xWwZqKnX8TZjhBA1Yu6+qyzL
  dGWSffKodUu6ZRkuhCsvbq8/bCenKA4UoPsV8jDEDOPdyWKj/+PFmK9WHZNMvmSc
  V2kXfwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTXeRQvpqCK
  YKX5uELqo4fFAjZa6zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
  AKPmTeXrx8K4NIE4cqqb6/ogXe9dfyuGUDGBp2VQH3ZxQL36o44IUoCojTAnPgrm
  SGvlyalcQbBWWMNK/7aKUAB1MwBUoVbip46KnMOJkbfpDRSeAhQZXsAju+iP3msB
  YPzEZO7vOeUwAPan+EiHhlq83JQiGPfyqX5FI+mhDtEYsew+01ZuQo9x9tXMwaFX
  MaYsl492DCB+uZ5RFE8hoQLVFGtAQcrWRTlv+KiswzyVb15KnaXUFzkBwGxYDnps
  uCnE7+atRLX4CnL3Gwp9WNsF9Sq3OxLd8+Y7us1AlBydaipCUVswwYNQO6xTA2DR
  EYs7x1fxMhIqnxM/kTGhPGk=
  -----END CERTIFICATE-----`

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
