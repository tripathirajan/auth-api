import { Types } from 'mongoose';
import { HttpStatus } from './enums';
export type Result = any | any[];

export type APIResult = {
  data: Result;
  message: string;
  success: boolean;
};
export interface IHttpResponse extends APIResult {
  readonly status: HttpStatus;
  toJson(): string;
  getResult(): APIResult;
  getStatus(): HttpStatus;
}

export type ControllerFun = (...args: any[]) => Promise<IHttpResponse>;
export type ControllerPayload = {
  query?: any;
  body?: any;
  params?: any;
  loggedInUserId: Types.ObjectId;
  cookies?: any;
};
