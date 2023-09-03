import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { AccessAndRefreshTokens, ITokenDoc, TokenType } from './token.types';
import Token from './token.model';
import { IUserDocument, ValidationResult, getUserByEmail } from '../user';

/**
 * generate token
 * @param userId
 * @param expires
 * @param type
 * @returns
 */
export const generateToken = (userId: mongoose.Types.ObjectId, expiresIn: string, type: string) => {
  if (!process.env.TOKEN_SECRET) {
    throw new Error(' Please add TOKEN_SECRET in .env');
  }
  const payload = {
    sub: userId,
    iat: new Date().getTime(),
    type,
  };
  return jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn });
};
/**
 * add new token
 * @param token
 * @param userId
 * @param expires
 * @param type
 * @param blacklisted
 * @returns
 */
export const addNewToken = async (
  token: string,
  userId: mongoose.Types.ObjectId,
  expiresIn: string,
  type: string,
  blacklisted: boolean = false,
): Promise<ITokenDoc> => {
  const tokenDoc = await Token.create({
    token,
    user: userId,
    expiresIn,
    type,
    blacklisted,
  });
  return tokenDoc;
};

/**
 * verify token
 * @param token
 * @param type
 * @returns
 */
export const verifyToken = async (token: string, type: string): Promise<ITokenDoc | ValidationResult> => {
  if (!process.env.TOKEN_SECRET) {
    throw new Error(' Please add TOKEN_SECRET in .env');
  }
  const payload = jwt.verify(token, process.env.TOKEN_SECRET);
  if (typeof payload.sub !== 'string') {
    return { isValid: false, error: 'Invalid token' };
  }
  const tokenDoc = await Token.findOne({
    token,
    type,
    user: payload.sub,
    blacklisted: false,
  });
  if (!tokenDoc) {
    return { isValid: false, error: 'Token not found' };
  }
  return tokenDoc;
};

/**
 * generate auth token
 * @param user
 * @returns
 */
export const generateAuthTokens = async (user: IUserDocument): Promise<AccessAndRefreshTokens> => {
  if (!process.env.ACCESS_TOKEN_EXPIRE_IN) {
    throw new Error('ACCESS_TOKEN_EXPIRE_IN is not set');
  }
  if (!process.env.REFRESH_TOKEN_EXPIRE_IN) {
    throw new Error('REFRESH_TOKEN_EXPIRE_IN is not set');
  }
  const accessTokenExpires = process.env.ACCESS_TOKEN_EXPIRE_IN || '1h';
  const accessToken = generateToken(user.id, accessTokenExpires, TokenType.ACCESS);

  const refreshTokenExpires = process.env.REFRESH_TOKEN_EXPIRE_IN || '7d';
  const refreshToken = generateToken(user.id, refreshTokenExpires, TokenType.REFRESH);
  await addNewToken(refreshToken, user.id, refreshTokenExpires, TokenType.REFRESH);

  return {
    access: {
      token: accessToken,
      expiresIn: accessTokenExpires,
    },
    refresh: {
      token: refreshToken,
      expiresIn: refreshTokenExpires,
    },
  };
};

/**
 * Generate reset password token
 * @param {string} email
 * @returns {Promise<string | ValidationResult>}
 */
export const generateResetPasswordToken = async (email: string): Promise<string | ValidationResult> => {
  if (!process.env.RESET_PASSWORD_TOKEN_EXPIRE_IN) {
    throw new Error('RESET_PASSWORD_TOKEN_EXPIRE_IN is not set');
  }
  const user = await getUserByEmail(email);
  if (!user) {
    return { isValid: false, error: 'User not found' } as ValidationResult;
  }
  const expires = process.env.RESET_PASSWORD_TOKEN_EXPIRE_IN || '5m';
  const resetPasswordToken = generateToken(user.id, expires, TokenType.RESET_PASSWORD);
  await addNewToken(resetPasswordToken, user.id, expires, TokenType.RESET_PASSWORD);
  return resetPasswordToken;
};

/**
 * Generate verify email token
 * @param {IUserDocument} user
 * @returns {Promise<string>}
 */
export const generateVerifyEmailToken = async (user: IUserDocument): Promise<string> => {
  if (!process.env.VERIFY_EMAIL_TOKEN_EXPIRE_IN) {
    throw new Error('VERIFY_EMAIL_TOKEN_EXPIRE_IN is not set');
  }
  const expires = process.env.VERIFY_EMAIL_TOKEN_EXPIRE_IN || '5m';
  const verifyEmailToken = generateToken(user.id, expires, TokenType.VERIFY_EMAIL);
  await addNewToken(verifyEmailToken, user.id, expires, TokenType.VERIFY_EMAIL);
  return verifyEmailToken;
};

/**
 * get token
 * @param token
 * @param type
 * @param blacklisted
 * @returns
 */
export const getToken = async (
  token: string,
  type: TokenType,
  blacklisted: boolean = false,
): Promise<ITokenDoc | null> => {
  const refreshTokenDoc = await Token.findOne({ token, type, blacklisted });
  return refreshTokenDoc;
};
