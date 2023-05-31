import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * No content
 */
export class NoContent extends BaseAPIResult {
  constructor(message: string) {
    super(HttpStatus.NO_CONTENT, message, {});
  }
}
