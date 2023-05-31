import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * Not found
 */
export class NotFound extends BaseAPIResult {
  constructor(message: string) {
    super(HttpStatus.NOT_FOUND, message, {});
  }
}
