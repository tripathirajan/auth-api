import { Types } from 'mongoose';
import User from './user.model';
import { IUserDocument, NewCreatedUser, NewRegisteredUser, UpdateUserBody } from './user.types';
import { QueryResult, UIFilter } from '../apiHelper';

/**
 * create new user
 * @param userInfo
 * @param auditorId
 * @returns
 */
export const createNewUser = async (
  userInfo: NewCreatedUser | NewRegisteredUser,
  auditorId?: Types.ObjectId,
): Promise<IUserDocument | null> => {
  // create new user
  if ('createdBy' in userInfo && 'updatedBy' in userInfo && auditorId) {
    userInfo.createdBy = auditorId;
    userInfo.updatedBy = auditorId;
  }
  const createdUser = await User.create(userInfo);
  return createdUser;
};

/**
 * check email already registered
 * @param email
 * @returns
 */
export const isEmailAlreadyRegistered = async (email: string): Promise<boolean> => {
  return await User.isEmailAlreadyExists(email);
};

/**
 * get user by id
 * @param userId
 * @returns
 */
export const getUserById = async (userId: Types.ObjectId): Promise<IUserDocument | null> => {
  return await User.findById(userId);
};

/**
 * get user by email
 * @param {String} email
 * @returns
 */
export const getUserByEmail = async (email: string): Promise<IUserDocument | null> => {
  return await User.findOne({ email });
};

/**
 * update user info
 * @param userId
 * @param updateBody
 * @returns
 */
export const updateUserInfo = async (
  userId: Types.ObjectId,
  updateBody: UpdateUserBody,
  actionBy: Types.ObjectId,
): Promise<IUserDocument | null> => {
  const user = await getUserById(userId);
  if (!user) {
    return null;
  }
  if (updateBody.email && (await User.isEmailAlreadyExists(updateBody.email, userId))) {
    return null;
  }
  Object.assign(user, { ...updateBody, updatedBy: actionBy });
  await user.save();
  return user;
};

/**
 * hard delete user by id
 * @param id
 * @returns
 */
export const deleteUserById = async (id: Types.ObjectId): Promise<boolean> => {
  const user = await getUserById(id);
  if (!user) return false;
  await user.deleteOne();
  return true;
};

/**
 * soft delete user by id
 * @param id
 * @returns
 */
export const softDeleteUserById = async (id: Types.ObjectId, actionBy: Types.ObjectId): Promise<boolean> => {
  const user = await getUserById(id);
  if (!user) {
    return false;
  }

  Object.assign(user, { isActive: false, isDeleted: true, updatedBy: actionBy });
  await user.save();
  return true;
};

/**
 * get all users
 * @param {UIFilter} param0
 * @param {Types.ObjectId} excludeUserId
 * @returns
 */
export const getAllUsers = (
  { filters, ...rest }: UIFilter,
  excludeUserId?: Types.ObjectId,
): Promise<QueryResult | null> => {
  if (excludeUserId !== undefined) {
    filters = { ...filters, _id: { $ne: excludeUserId } };
  }
  const userList = User.getFilteredRecord({ where: { ...filters }, ...rest });
  return userList;
};
