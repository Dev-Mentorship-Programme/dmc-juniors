import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
  tokenId?: string;
}

export interface RefreshTokenPayload {
  userId: string;
  tokenId: string;
}

export class JWTService {
  private static readonly JWT_SECRET: string = process.env.JWT_SECRET || 'fallback-secret';
  private static readonly JWT_REFRESH_SECRET: string = process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret';
  private static readonly JWT_EXPIRES_IN: string = process.env.JWT_EXPIRES_IN || '15m';
  private static readonly JWT_REFRESH_EXPIRES_IN: string = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

  /**
   * Generate access token
   */
  static generateAccessToken(payload: TokenPayload): string {
    const tokenPayload = {
      ...payload,
      tokenId: uuidv4(),
      type: 'access'
    };

    return jwt.sign(tokenPayload, this.JWT_SECRET, {
      expiresIn: this.JWT_EXPIRES_IN,
      issuer: 'jwt-auth-demo',
      audience: 'jwt-auth-demo-users'
    } as SignOptions);
  }

  /**
   * Generate refresh token
   */
  static generateRefreshToken(payload: RefreshTokenPayload): string {
    const tokenPayload = {
      ...payload,
      type: 'refresh'
    };

    return jwt.sign(tokenPayload, this.JWT_REFRESH_SECRET, {
      expiresIn: this.JWT_REFRESH_EXPIRES_IN,
      issuer: 'jwt-auth-demo',
      audience: 'jwt-auth-demo-users'
    } as SignOptions);
  }

  /**
   * Verify access token
   */
  static verifyAccessToken(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET, {
        issuer: 'jwt-auth-demo',
        audience: 'jwt-auth-demo-users'
      }) as any;

      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return {
        userId: decoded.userId,
        email: decoded.email,
        role: decoded.role,
        tokenId: decoded.tokenId
      };
    } catch (error) {
      throw new Error('Invalid or expired access token');
    }
  }

  /**
   * Verify refresh token
   */
  static verifyRefreshToken(token: string): RefreshTokenPayload {
    try {
      const decoded = jwt.verify(token, this.JWT_REFRESH_SECRET, {
        issuer: 'jwt-auth-demo',
        audience: 'jwt-auth-demo-users'
      }) as any;

      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      return {
        userId: decoded.userId,
        tokenId: decoded.tokenId
      };
    } catch (error) {
      throw new Error('Invalid or expired refresh token');
    }
  }

  /**
   * Generate token pair (access + refresh)
   */
  static generateTokenPair(userPayload: TokenPayload): { accessToken: string; refreshToken: string; tokenId: string } {
    const tokenId = uuidv4();
    
    const accessToken = this.generateAccessToken({
      ...userPayload,
      tokenId
    });

    const refreshToken = this.generateRefreshToken({
      userId: userPayload.userId,
      tokenId
    });

    return {
      accessToken,
      refreshToken,
      tokenId
    };
  }

  /**
   * Extract token from Authorization header
   */
  static extractTokenFromHeader(authHeader?: string): string | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7);
  }

  /**
   * Get token expiration time
   */
  static getTokenExpiration(token: string): Date | null {
    try {
      const decoded = jwt.decode(token) as any;
      if (decoded && decoded.exp) {
        return new Date(decoded.exp * 1000);
      }
      return null;
    } catch (error) {
      return null;
    }
  }
}
