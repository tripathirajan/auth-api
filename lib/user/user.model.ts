import mongoose from 'mongoose';
import { IUserDocument, IUserModel } from './user.types';
import { HashingAgent } from '@tripathirajan/crypto-service';
import { filterRecords, toJSON } from '../apiHelper';

const Schema = mongoose.Schema;
const userSchema = new Schema<IUserDocument, IUserModel>(
  {
    firstName: {
      type: String,
      required: true,
      trim: true,
    },
    middleName: {
      type: String,
      required: false,
      trim: true,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
      trim: true,
    },
    roles: {
      type: [String],
      default: ['user'],
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    isDeleted: {
      type: Boolean,
      default: false,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    image: {
      type: String,
    },
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: false,
    },
    updatedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: false,
    },
  },
  {
    timestamps: true,
  },
);

userSchema.plugin(toJSON);
userSchema.plugin(filterRecords);

userSchema.static(
  'isEmailAlreadyExists',
  async function (email: string, excludeUserId: mongoose.ObjectId): Promise<boolean> {
    const user = await this.findOne({ email, _id: { $ne: excludeUserId } });
    return !!user;
  },
);

userSchema.method('hasPasswordMatched', async function (password: string): Promise<boolean> {
  const user = this;
  return await HashingAgent.compareHash(password, user.password);
});
userSchema.method('isUserActive', function (password: string): boolean {
  const { isActive } = this;
  return !!isActive;
});
userSchema.method('isUserDeleted', function (password: string): boolean {
  const { isDeleted } = this;
  return !!isDeleted;
});
userSchema.method('isAdminUser', function (password: string): boolean {
  const { roles } = this;
  if (Array.isArray(roles) && roles.includes('Admin')) return true;
  return false;
});

userSchema.pre('save', async function (next) {
  const user = this;
  if (user.isModified('password')) {
    user.password = await HashingAgent.getHash(user.password, 8);
  }
  next();
});

const User = mongoose.model<IUserDocument, IUserModel>('User', userSchema);

export default User;
