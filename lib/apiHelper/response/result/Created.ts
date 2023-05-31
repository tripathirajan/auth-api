import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * Created
 */
export class Created extends BaseAPIResult {
  constructor(message: string, data?: Result) {
    super(HttpStatus.CREATED, message, data);
  }
}
