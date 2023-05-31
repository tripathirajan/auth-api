export type SortOrder = 'asc' | 'desc';

export type Sorting = {
  dir: SortOrder;
  field: string;
};
export type Pagination = {
  page: number;
  limit: number;
};
export type ProjectedField = {
  field: string;
  show: boolean;
};
export type CommonFilter = {
  sorting?: Sorting[];
  pagination?: Pagination;
  fields?: ProjectedField[];
};
export type UIFilter = CommonFilter & {
  filters?: Record<string, any>;
};
export type RecordFilter = CommonFilter & {
  where?: Record<string, any>;
};
export type QueryFilter = RecordFilter & {
  populate?: string;
};

export interface QueryResult {
  results: Document[];
  page: number;
  limit: number;
  totalPages: number;
  totalRecord: number;
}
