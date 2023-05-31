import { JwtPayload } from 'jsonwebtoken';
import { Document, Model, Types } from 'mongoose';
import { IUserDocument } from '../user/user.types';

export interface IUserWithTokens {
  user: IUserDocument;
  tokens: AccessAndRefreshTokens;
}

export interface IToken {
  token: string;
  user: string;
  type: string;
  expires: Date;
  blacklisted: boolean;
}

export type NewToken = Omit<IToken, 'blacklisted'>;

export interface ITokenDoc extends IToken, Document {}

export interface ITokenModel extends Model<ITokenDoc> {}

export interface IPayload extends JwtPayload {
  sub: string;
  iat: number;
  exp: number;
  type: string;
}

export interface TokenPayload {
  token: string;
  expires: Date;
}

export interface AccessAndRefreshTokens {
  access: TokenPayload;
  refresh: TokenPayload;
}

export enum TokenType {
  REFRESH = 'refresh',
  RESET_PASSWORD = 'resetToken',
  VERIFY_EMAIL = 'verifyEmail',
  ACCESS = 'access',
}
