import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * Bad request
 */
export class BadRequest extends BaseAPIResult {
  constructor(message: string) {
    super(HttpStatus.BAD_REQUEST, message, {});
  }
}
