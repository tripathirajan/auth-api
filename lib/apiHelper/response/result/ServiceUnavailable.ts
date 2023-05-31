import BaseAPIResult from './BaseAPIResult';
import { HttpStatus } from '../enums';
import { Result } from '../types';

/**
 * Service unavailable
 */
export class ServiceUnavailable extends BaseAPIResult {
  constructor(message: string) {
    super(HttpStatus.SERVICE_UNAVAILABLE, message, {});
  }
}
