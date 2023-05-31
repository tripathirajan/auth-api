import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * Success
 */
export class Success extends BaseAPIResult {
  constructor(message: string, data: Result) {
    super(HttpStatus.OK, message, data);
  }
}
