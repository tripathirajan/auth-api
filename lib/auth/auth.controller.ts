import {
  BadRequest,
  ControllerPayload,
  IHttpResponse,
  Success,
  Unauthorized,
  asyncControllerHandler,
  asyncAuthControllerHandler,
  InternalServerError,
  NoContent,
} from '../apiHelper';
import { EMAIL_REGEX_PATTERN, PASSWORD_PATTERN_NORMAL, REFRESH_TOKEN_COOKIE_NAME } from '../apiHelper/constants';
import {
  NewRegisteredUser,
  ValidationResult,
  createNewUser,
  getUserByEmail,
  getUserById,
  isEmailAlreadyRegistered,
  updateUserInfo,
  validateNewUserData,
} from '../user';
import { TokenType, generateAuthTokens, verifyToken, ITokenDoc, getToken, generateResetPasswordToken } from '../token';
import { Types } from 'mongoose';
import { MailServiceManager } from '@tripathirajan/mail-service';
import { resetPasswordTemplate } from './email-templates';
import Token from '../token/token.model';

if (process.env.RESET_PASSWORD_URL === undefined) {
  throw new Error('Add RESET_PASSWORD_URL to .env');
}
if (process.env.MAIL_SENT_FROM === undefined) {
  throw new Error('Add MAIL_SENT_FROM to .env');
}
/**
 * login user
 */
export const login = asyncAuthControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const { email, password } = data.body;
  if (!email || !EMAIL_REGEX_PATTERN.test(email) || !password) {
    return new BadRequest('Incorrect credentials');
  }
  const user = await getUserByEmail(email);
  if (!user || !(await user.hasPasswordMatched(password))) {
    return new Unauthorized('Incorrect credentials');
  }
  const tokens = await generateAuthTokens(user);
  if (!tokens) {
    return new Unauthorized('Unable to login, please try again.');
  }
  return new Success('Success', { user, tokens });
});

/**
 * register
 */
export const register = asyncAuthControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const { body } = data;
  const { isValid, error }: ValidationResult = await validateNewUserData(body);
  if (!isValid) {
    return new BadRequest(error);
  }
  if (await isEmailAlreadyRegistered(body.email)) {
    return new BadRequest('Email already registered.');
  }
  const user = await createNewUser(body as NewRegisteredUser);
  if (!user) return new Unauthorized('Unable to register');
  const tokens = await generateAuthTokens(user);
  if (!tokens) return new Unauthorized('Registration successful! please try to login.');
  return new Success('Success', { user, tokens });
});

/**
 * refresh token
 */
export const refreshToken = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const { cookies } = data;
  const refreshToken = cookies && cookies[REFRESH_TOKEN_COOKIE_NAME];
  if (!refreshToken) return new Unauthorized('Unauthorized');
  const result = await verifyToken(refreshToken, TokenType.REFRESH);
  if ('isValid' in result && !result.isValid) return new Unauthorized(result.error);
  let user = null;
  if ('user' in result) {
    user = await getUserById(new Types.ObjectId(result.user));
  }
  if (!user || user === null) return new Unauthorized('Unauthorized');
  await (result as ITokenDoc).deleteOne();
  const newTokens = await generateAuthTokens(user);
  return new Success('Success', { tokens: newTokens });
});

/**
 * logout
 */
export const logout = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const { cookies } = data;
  const refreshToken = cookies && cookies[REFRESH_TOKEN_COOKIE_NAME];
  if (!refreshToken) return new Unauthorized('Unauthorized');
  const token = await getToken(refreshToken, TokenType.REFRESH);
  if (!token) return new Unauthorized('Unauthorized');
  await token.deleteOne();
  return new Success('Success', {});
});

/**
 * forgot password
 */
export const forgotPassword = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const { email } = data.body;
  if (!email || !EMAIL_REGEX_PATTERN.test(email)) return new BadRequest('Invalid email');
  const user = await getUserByEmail(email);
  if (!user) return new BadRequest('Email not registered');

  const resetPasswordToken = await generateResetPasswordToken(user.email);
  if (!resetPasswordToken) return new InternalServerError('Unable to generate reset password token');
  const resetURL = `${process.env.RESET_PASSWORD_URL}?token=${resetPasswordToken}`;
  // send reset link to email
  const emailAgent = MailServiceManager.getInstance();
  emailAgent.sendHTMLMail({
    to: user.email,
    subject: 'Reset Password',
    body: resetPasswordTemplate(`${user.firstName} ${user.lastName}`, resetURL).html,
    from: process.env.MAIL_SENT_FROM || 'no-reply@gmail.com',
  });
  return new NoContent('Reset link sent');
});

/**
 * reset forgot password
 */
export const resetPassword = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const {
    query: { token },
    body: { password },
  } = data;
  if (!token || !password) return new Unauthorized('Unable to reset password, please try again.');
  if (!PASSWORD_PATTERN_NORMAL.test(password)) return new BadRequest('Please choose password with defined criteria.');
  const resetPassToken = await verifyToken(token, TokenType.RESET_PASSWORD);
  if ('isValid' in resetPassToken && !resetPassToken.isValid) return new Unauthorized(resetPassToken.error);
  let user = null;
  if ('user' in resetPassToken) {
    user = await getUserById(new Types.ObjectId(resetPassToken.user));
  }
  if (!user || user === null) return new Unauthorized('Invalid token');
  await updateUserInfo(user._id, { password: password }, user._id);
  await Token.deleteMany({ user: user._id, type: TokenType.RESET_PASSWORD });
  return new Success('Success', {});
});

/**
 * verify user email
 */
export const verifyUserEmail = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  return new Success('Success', {});
});
