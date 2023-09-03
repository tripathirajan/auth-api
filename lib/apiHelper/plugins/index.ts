import { Schema, Document, Model } from 'mongoose';
import { Request, Response, NextFunction } from 'express';
import { QueryFilter, QueryResult } from '../filters/types';
import { ControllerFun, IHttpResponse } from '../response/types';
import { HttpStatus } from '../response';
import { AccessAndRefreshTokens } from '../../token';
import { PATTERN_ALPHA, PATTERN_NUMBER, REFRESH_TOKEN_COOKIE_NAME } from '../constants';
import dayjs, { ManipulateType } from 'dayjs';

/**
 *
 * @param obj
 * @param path
 * @param index
 * @returns
 */
const removeAtPath = (obj: any, path: any, index: number) => {
  if (index === path.length - 1) {
    // eslint-disable-next-line no-param-reassign
    delete obj[path[index]];
    return;
  }
  removeAtPath(obj[path[index]], path, index + 1);
};

/**
 *
 * @param {any} schema
 */
export const toJSON = (schema: any) => {
  let transform: (...args: any[]) => void;
  if (schema.options.toJSON && schema.options.toJSON.transform) {
    transform = schema.options.toJSON.transform;
  }
  schema.options.toJSON = Object.assign(schema.options.toJSON || {}, {
    transform(doc: Document, ret: any, options: Record<string, any>) {
      Object.keys(schema.paths).forEach((path) => {
        if (schema.paths[path].options && schema.paths[path].options.private) {
          removeAtPath(ret, path.split('.'), 0);
        }
      });

      // eslint-disable-next-line no-param-reassign
      ret.id = ret._id.toString();
      // eslint-disable-next-line no-param-reassign
      delete ret._id;
      // eslint-disable-next-line no-param-reassign
      delete ret.__v;
      // eslint-disable-next-line no-param-reassign
      delete ret.createdAt;
      // eslint-disable-next-line no-param-reassign
      delete ret.updatedAt;
      if (transform) {
        return transform(doc, ret, options);
      }
    },
  });
};

/**
 * filter records
 * @param schema
 */
export const filterRecords = <T extends Document, U extends Model<U>>(schema: Schema<T>): void => {
  schema.static('getFilteredRecord', async function (filter: QueryFilter): Promise<QueryResult> {
    let sort: string = 'createdAt';
    const { sorting, pagination, where, fields, populate } = filter;
    // sorting
    const sortingCriteria: any = [];
    if (sorting && Array.isArray(sorting) && sorting.length > 0) {
      for (const sortEl of sorting) {
        sortingCriteria.push(`${sortEl.dir === 'desc' ? '-' : ''}${sortEl.field}`);
      }
      sort = sortingCriteria.join(' ');
    }
    // pagination
    let page: number = 1;
    let limit: number = 10;
    let skip: number = 0;
    if (pagination) {
      page = parseInt(pagination.page.toString(), 10) || 1;
      limit = parseInt(pagination.limit.toString(), 10) || 10;
      skip = (page - 1) * limit;
    }
    // projection
    let projection: string = '-createdAt -updatedAt';
    if (fields && Array.isArray(fields) && fields.length > 0) {
      const projectionCriteria: any = [];
      for (const field of fields) {
        projectionCriteria.push(`${!field.show ? '-' : ''}${field.field}`);
      }
      projection = projectionCriteria.join(' ');
    }
    let whereObj: Record<string, any> = { isDeleted: false };
    if (where) {
      whereObj = { ...whereObj, ...where };
    }
    const countPromise = this.countDocuments(where).exec();
    let docsPromise = this.find(whereObj).sort(sort).skip(skip).limit(limit).select(projection);

    // populate record
    if (populate !== undefined) {
      populate.split(',').forEach((populateOption: any) => {
        docsPromise = docsPromise.populate(
          populateOption
            .split('.')
            .reverse()
            .reduce((a: string, b: string) => ({ path: b, populate: a })),
        );
      });
    }
    docsPromise = docsPromise.exec();

    return Promise.all([countPromise, docsPromise]).then((values) => {
      const [totalRecord, results] = values;
      const totalPages = Math.ceil(totalRecord / limit);
      const result = {
        results,
        page,
        limit,
        totalPages,
        totalRecord,
      };
      return Promise.resolve(result);
    });
  });
};

/**
 * async handler
 */
export const asyncHandler = (func: any) => (req: Request, res: Response, next: NextFunction) => {
  Promise.resolve(func(req, res, next)).catch((err) => next(err));
};

/**
 * async controller handler
 * @param func
 * @returns
 */
export const asyncControllerHandler = (func: ControllerFun) =>
  asyncHandler(async (req: Request, res: Response) => {
    const { loggedInUserId, query, body, params, cookies } = req as any;
    const response = (await func({ query, body, params, loggedInUserId, cookies })) as IHttpResponse;
    return res.status(response.status).json(response.getResult());
  });

/**
 * async auth controller handler
 * @param func
 * @returns
 */
export const asyncAuthControllerHandler = (func: ControllerFun) =>
  asyncHandler(async (req: Request, res: Response) => {
    const { loggedInUserId, query, body, params, cookies } = req as any;
    const response = (await func({ query, body, params, loggedInUserId, cookies })) as IHttpResponse;
    if (response.status === HttpStatus.OK) {
      const {
        refresh: { token, expiresIn },
      } = response?.data?.tokens as AccessAndRefreshTokens;
      if (token && expiresIn) {
        const unitData: ManipulateType = (expiresIn.toString().match(PATTERN_ALPHA) || 'd') as ManipulateType;
        const amountData: number = parseInt((expiresIn.toString().match(PATTERN_NUMBER) || '7').toString(), 10);
        res.cookie(REFRESH_TOKEN_COOKIE_NAME, token, {
          httpOnly: true, // accessible only by web server
          secure: true, // https
          sameSite: 'none', // cross-site cookie
          expires: new Date(dayjs().add(amountData, unitData).toString()), // 7 * 24 * 60 * 60 * 1000 //cookie expiry: set to match rT
        });
        delete response?.data?.tokens?.refresh;
      }
    }
    return res.status(response.status).json(response.getResult());
  });
