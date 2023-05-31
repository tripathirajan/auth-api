import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * Internal server error
 */
export class InternalServerError extends BaseAPIResult {
  constructor(message: string) {
    super(HttpStatus.INTERNAL_SERVER_ERROR, message, {});
  }
}
