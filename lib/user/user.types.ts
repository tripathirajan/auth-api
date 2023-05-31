import { Document, Model, Types } from 'mongoose';
import { QueryFilter, QueryResult } from '../apiHelper/filters/types';

export interface IAudit {
  createdBy: Types.ObjectId;
  updatedBy: Types.ObjectId;
  isDeleted: boolean;
  isActive: boolean;
}

export interface IUser extends IAudit {
  firstName: string;
  middleName: string;
  lastName: string;
  email: string;
  password: string;
  roles: string[];
  image: string;
  isEmailVerified: boolean;
}

export interface IUserDocument extends IUser, Document {
  hasPasswordMatched(password: string): Promise<boolean>;
  isUserActive(): boolean;
  isUserDeleted(): boolean;
  isAdminUser(): boolean;
}

export interface IUserModel extends Model<IUserDocument> {
  isEmailAlreadyExists(email: string, excludeUserId?: Types.ObjectId): Promise<boolean>;
  getFilteredRecord(queryFilter: QueryFilter): Promise<QueryResult | null>;
}

export type UpdateUserBody = Partial<IUser>;

export type NewRegisteredUser = Omit<
  IUser,
  | 'roles'
  | 'isEmailVerified'
  | 'resetToken'
  | 'resetTokenExpireOn'
  | 'createdBy'
  | 'updatedBy'
  | 'isDeleted'
  | 'image'
  | 'isActive'
>;

export type NewCreatedUser = Omit<IUser, 'isEmailVerified' | 'resetToken' | 'resetTokenExpireOn' | 'isDeleted'>;
export type NewUser = Omit<
  IUser,
  'isEmailVerified' | 'resetToken' | 'resetTokenExpireOn' | 'createdBy' | 'updatedBy' | 'isDeleted'
>;

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
  SUPER_ADMIN = 'superAdmin',
}
