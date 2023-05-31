import { Types } from 'mongoose';
import { HttpStatus } from './enums';
export type Result = any | any[];

export interface IHttpResponse {
  status: HttpStatus;
  data: Result;
  message: string;
  success: boolean;
  toJson(): string;
}

export type ControllerFun = (...args: any[]) => Promise<IHttpResponse>;
export type ControllerPayload = {
  query?: any;
  body?: any;
  params?: any;
  loggedInUserId: Types.ObjectId;
  cookies?: any;
};
