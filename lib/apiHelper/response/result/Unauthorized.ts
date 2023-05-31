import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * Unauthorized
 */
export class Unauthorized extends BaseAPIResult {
  constructor(message: string) {
    super(HttpStatus.UNAUTHORIZED, message, {});
  }
}
