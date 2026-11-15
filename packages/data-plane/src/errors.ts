import {
  DATA_PLANE_ERROR_CODES,
  DataPlaneAccessError,
  type DataPlaneErrorCode,
} from "@hunt-command/shared";

export type ExtendedDataPlaneErrorCode =
  | DataPlaneErrorCode
  | "invalid_expression"
  | "regex_not_supported"
  | "no_intel_source"
  | "no_lab_browser"
  | "window_not_closed"
  | "cursor_expired"
  | "unknown_citation"
  | "host_not_allowed"
  | "caller_not_authorized"
  | "key_not_read_only"
  | "key_in_bot_profile"
  | "profile_unreadable"
  | "explicit_case_id_required"
  | "case_mismatch"
  | "invalid_dataset"
  | "invalid_pagination"
  | "invalid_arguments"
  | "not_found"
  | "backend_not_ready"
  | "packet_tool_error";

export type DataPlaneHttpStatus = 400 | 401 | 403 | 404 | 405 | 503;

const SHARED_ERROR_SET: ReadonlySet<string> = new Set<string>(DATA_PLANE_ERROR_CODES);

export class DataPlaneServiceError extends Error {
  public readonly statusCode: DataPlaneHttpStatus;
  public readonly errorCode: ExtendedDataPlaneErrorCode;

  constructor(
    statusCode: DataPlaneHttpStatus,
    errorCode: ExtendedDataPlaneErrorCode,
    message?: string,
  ) {
    super(message ?? `${statusCode} ${errorCode}`);
    this.name = "DataPlaneServiceError";
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}

export function throwDataPlaneError(
  statusCode: DataPlaneHttpStatus,
  errorCode: ExtendedDataPlaneErrorCode,
  message?: string,
): never {
  if (
    (statusCode === 400 || statusCode === 403 || statusCode === 405) &&
    SHARED_ERROR_SET.has(errorCode)
  ) {
    throw new DataPlaneAccessError(statusCode, errorCode as DataPlaneErrorCode, message);
  }
  throw new DataPlaneServiceError(statusCode, errorCode, message);
}

export function extractDataPlaneError(err: unknown): {
  statusCode: DataPlaneHttpStatus;
  errorCode: ExtendedDataPlaneErrorCode;
} | null {
  if (err instanceof DataPlaneAccessError) {
    return { statusCode: err.statusCode, errorCode: err.errorCode };
  }
  if (err instanceof DataPlaneServiceError) {
    return { statusCode: err.statusCode, errorCode: err.errorCode };
  }
  return null;
}
