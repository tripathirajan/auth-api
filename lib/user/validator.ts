import { EMAIL_REGEX_PATTERN, PASSWORD_PATTERN_NORMAL } from '../apiHelper/constants';
import { isEmailAlreadyRegistered } from './user.service';
import { NewCreatedUser, UpdateUserBody, UserRole } from './user.types';

export type ValidationResult = {
  isValid: boolean;
  error: string;
};
/**
 * validate new user data
 * @param userData
 * @returns
 */
export const validateNewUserData = async (userData: NewCreatedUser): Promise<ValidationResult> => {
  let toReturn: ValidationResult = {
    isValid: true,
    error: '',
  };
  const { firstName, middleName, lastName, email, password, roles } = userData;
  // email validation
  if (!email || !EMAIL_REGEX_PATTERN.test(email)) {
    toReturn = {
      isValid: false,
      error: 'Email is required and must be a valid email',
    };
    return toReturn;
  }
  if (await isEmailAlreadyRegistered(email)) {
    toReturn = {
      isValid: false,
      error: 'Email is already registered',
    };
    return toReturn;
  }
  // name validation
  if (!firstName || [...firstName].length <= 2 || [...firstName].length >= 100) {
    toReturn = {
      isValid: false,
      error: 'First name is required and must be at least 2 and max 100  characters long',
    };
    return toReturn;
  }
  if ((middleName && [...middleName].length <= 2) || [...middleName].length >= 100) {
    toReturn = {
      isValid: false,
      error: 'Middle name must be at least 2  and max 100 characters long',
    };
    return toReturn;
  }
  if (!lastName || [...lastName].length <= 2 || [...lastName].length >= 100) {
    toReturn = {
      isValid: false,
      error: 'Last name is required and must be at least 2 and max 100 characters long',
    };
    return toReturn;
  }
  // password validation
  if (!password || !PASSWORD_PATTERN_NORMAL.test(password)) {
    toReturn = {
      isValid: false,
      error: `Password is required and must have at-least:
        - 1-capital letter
        - 1 number
        - 1 lowercase alphabet
        - Min 8 character
        - Max 25 character
        - Allowed (!@#$%^&*) special character`,
    };
    if (
      !roles ||
      !Array.isArray(roles) ||
      roles.length === 0 ||
      (!roles.includes(UserRole.USER) && !roles.includes(UserRole.ADMIN))
    ) {
      toReturn = {
        isValid: false,
        error: 'User role is required',
      };
    }
    return toReturn;
  }
  return toReturn;
};

/**
 * validate password
 * @param password
 * @param confirmPassword
 * @returns
 */
export const validatePassword = (password: string, confirmPassword?: string) => {
  const result: ValidationResult = {
    isValid: true,
    error: '',
  };
  if (!password || !PASSWORD_PATTERN_NORMAL.test(password)) {
    result.error = 'Not a valid password';
    result.isValid = false;
    return result;
  }
  if (confirmPassword && confirmPassword !== password) {
    result.error = 'Password not matching';
    result.isValid = false;
    return result;
  }
  return result;
};

/**
 * validate user info for update
 * @param userData
 * @returns
 */
export const validateUpdateUserData = (userData: UpdateUserBody): ValidationResult => {
  let toReturn: ValidationResult = {
    isValid: true,
    error: '',
  };
  const { firstName, lastName, middleName = '', roles } = userData;
  // name validation
  if (!firstName || [...firstName].length <= 2 || [...firstName].length >= 100) {
    toReturn = {
      isValid: false,
      error: 'First name is required and must be at least 2 and max 100  characters long',
    };
    return toReturn;
  }
  if ((middleName && [...middleName].length <= 2) || [...middleName].length >= 100) {
    toReturn = {
      isValid: false,
      error: 'Middle name must be at least 2  and max 100 characters long',
    };
    return toReturn;
  }
  if (!lastName || [...middleName].length <= 2 || [...middleName].length >= 100) {
    toReturn = {
      isValid: false,
      error: 'Last name is required and must be at least 2 and max 100 characters long',
    };
    return toReturn;
  }
  // roles
  if (
    !roles ||
    !Array.isArray(roles) ||
    roles.length === 0 ||
    (!roles.includes(UserRole.USER) && !roles.includes(UserRole.ADMIN))
  ) {
    toReturn = {
      isValid: false,
      error: 'User role is required',
    };
  }
  return toReturn;
};
