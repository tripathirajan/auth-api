import { HttpStatus } from '../enums';
import { IHttpResponse } from '../types';

/**
 * Base api result
 */
class BaseAPIResult implements IHttpResponse {
  /**
   * Success
   */
  public success: boolean = true;

  /**
   * Status
   */
  public status: HttpStatus = HttpStatus.OK;

  /**
   * Message
   */
  public message: string;

  /**
   * Data
   */
  public data: any | any[];

  /**
   * Creates an instance of base api result.
   * @param status
   * @param message
   * @param [data]
   */
  constructor(status: HttpStatus, message: string, data: any | any[] = {}) {
    this.status = status;
    this.message = message;
    this.data = data;
    this.success = [HttpStatus.OK, HttpStatus.CREATED, HttpStatus.NO_CONTENT].includes(this.status);
  }

  /**
   * To json
   * @returns json
   */
  public toJson(): string {
    return JSON.stringify({
      data: this.data,
      message: this.message,
      success: this.success,
    });
  }
}

export default BaseAPIResult;
