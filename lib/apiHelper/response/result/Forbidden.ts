import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * Forbidden
 */
export class Forbidden extends BaseAPIResult {
  constructor(message: string) {
    super(HttpStatus.FORBIDDEN, message, {});
  }
}
