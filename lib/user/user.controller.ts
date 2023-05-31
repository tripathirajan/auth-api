import {
  BadRequest,
  Created,
  InternalServerError,
  NotFound,
  Success,
  UIFilter,
  asyncControllerHandler,
} from '../apiHelper';
import { NewCreatedUser } from './user.types';
import { ValidationResult, validateNewUserData, validatePassword, validateUpdateUserData } from './validator';
import {
  createNewUser,
  getAllUsers,
  getUserByEmail,
  getUserById,
  softDeleteUserById,
  updateUserInfo,
} from './user.service';
import { ControllerPayload, IHttpResponse } from '../apiHelper/response';

/**
 * add new user
 */
export const addNewUser = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const { body, loggedInUserId } = data;
  const newUserData: NewCreatedUser = body;
  const { isValid, error }: ValidationResult = await validateNewUserData(newUserData);
  if (!isValid) {
    return new BadRequest(error);
  }

  const createdUser = await createNewUser(newUserData, loggedInUserId);
  if (!createdUser) {
    return new InternalServerError('Not able to create user, please try again');
  }
  return new Created('User created!', createdUser);
});

/**
 * get all user list
 */
export const getAllUser = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const { loggedInUserId, query } = data;
  const { filter } = query;
  const userList = await getAllUsers(filter as UIFilter, loggedInUserId);
  if (!userList || userList?.totalRecord === 0) {
    return new NotFound('No data found!');
  }
  return new Success('Success!', userList);
});

/**
 * get user's info
 */
export const getUserInfo = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const {
    query: { userId },
  } = data;
  if (!userId) return new BadRequest('Bad request, please provide user id.');
  const userDetail = await getUserById(userId);
  if (!userDetail) return new NotFound('No user found!');
  return new Success('Success!', userDetail);
});
/**
 * update user
 */
export const updateUserDetails = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const {
    loggedInUserId,
    body: { firstName, middleName, lastName, roles },
    params: { id },
  } = data;
  if (!id) return new BadRequest('Bad request');
  // validate payload
  const { isValid, error } = validateUpdateUserData({ firstName, lastName, middleName, roles });
  if (!isValid) return new BadRequest(error);
  const updatedUser = await updateUserInfo(id, { firstName, middleName, lastName, roles }, loggedInUserId);
  return new Success('Success!', updatedUser);
});
/**
 * soft delete user
 */
export const deleteUser = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const {
    loggedInUserId,
    params: { id },
  } = data;
  const isDeleted = await softDeleteUserById(id, loggedInUserId);
  if (!isDeleted) return new InternalServerError('Internal server error, please try again.');
  return new Success('Success!', {});
});

/**
 * search for user
 */
export const searchUser = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const {
    loggedInUserId,
    query: { email },
  } = data;
  if (!email) return new BadRequest('Bad request!');
  const userInfo = await getUserByEmail(email);
  if (!userInfo || loggedInUserId === userInfo._id) return new NotFound('No record found!');
  return new Success('Success!', userInfo);
});

/**
 * mark user's account active/in-active
 */
export const activateDeactivateUser = asyncControllerHandler(
  async (data: ControllerPayload): Promise<IHttpResponse> => {
    const {
      loggedInUserId,
      params: { id },
      body: { status },
    } = data;
    if (!id || status === undefined) return new BadRequest('Bad request');
    const userInfo = await updateUserInfo(id, { isActive: !!status }, loggedInUserId);
    if (!userInfo) return new InternalServerError('Internal server error, please try again.');
    return new Success('Success!', userInfo);
  },
);

/**
 * change user account password
 */
export const changeUserPassword = asyncControllerHandler(async (data: ControllerPayload): Promise<IHttpResponse> => {
  const {
    loggedInUserId,
    body: { currentPassword, newPassword, confirmPassword },
  } = data;
  const result = validatePassword(newPassword, confirmPassword);
  if (!result.isValid) return new BadRequest(result.error);
  const userInfo = await getUserById(loggedInUserId);
  // check current password is correct or not
  const currentPasswordMatched = await userInfo?.hasPasswordMatched(currentPassword);
  if (!currentPasswordMatched) return new BadRequest('Current password incorrect');
  // check new password is same as current
  const newPasswordSameAsCurrent = await userInfo?.hasPasswordMatched(newPassword);
  if (newPasswordSameAsCurrent) return new BadRequest("New password can't be same as current password.");
  // update password
  const updatedUserInfo = await updateUserInfo(loggedInUserId, { password: newPassword }, loggedInUserId);
  return new Success('Success!', updatedUserInfo);
});
