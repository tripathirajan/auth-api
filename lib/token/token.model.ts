import mongoose from 'mongoose';
import { ITokenDoc, ITokenModel, TokenType } from './token.types';
import { toJSON } from '../apiHelper';

const Schema = mongoose.Schema;

const tokenSchema = new Schema<ITokenDoc, ITokenModel>(
  {
    token: {
      type: String,
      required: true,
      index: true,
    },
    user: {
      type: String,
      ref: 'User',
      required: true,
    },
    type: {
      type: String,
      enum: [TokenType.REFRESH, TokenType.RESET_PASSWORD, TokenType.VERIFY_EMAIL],
      required: true,
      default: TokenType.REFRESH,
    },
    expires: {
      type: Date,
      required: true,
    },
    blacklisted: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  },
);
// plugin
tokenSchema.plugin(toJSON);

const Token = mongoose.model<ITokenDoc, ITokenModel>('Token', tokenSchema);

export default Token;
