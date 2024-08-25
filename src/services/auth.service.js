const httpStatus = require('http-status');
const {
  Totp,
  generateBackupCodes,
} = require('time2fa');
const bcrypt = require('bcryptjs');
const config = require('../config/config');
const tokenService = require('./token.service');
const userService = require('./user.service');
const Token = require('../models/token.model');
const ApiError = require('../utils/ApiError');
const { tokenTypes } = require('../config/tokens');

/**
 * Login with username and password
 * @param {string} email
 * @param {string} password
 * @returns {Promise<User>}
 */
const loginUserWithEmailAndPassword = async (email, password) => {
  const user = await userService.getUserByEmail(email);
  if (!user || !(await user.isPasswordMatch(password))) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Incorrect email or password');
  }
  return user;
};

/**
 * Logout
 * @param {string} refreshToken
 * @returns {Promise}
 */
const logout = async (refreshToken) => {
  const refreshTokenDoc = await Token.findOne({ token: refreshToken, type: tokenTypes.REFRESH, blacklisted: false });
  if (!refreshTokenDoc) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Not found');
  }
  await refreshTokenDoc.remove();
};

/**
 * Refresh auth tokens
 * @param {string} refreshToken
 * @returns {Promise<Object>}
 */
const refreshAuth = async (refreshToken) => {
  try {
    const refreshTokenDoc = await tokenService.verifyToken(refreshToken, tokenTypes.REFRESH);
    const user = await userService.getUserById(refreshTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await refreshTokenDoc.remove();
    return tokenService.generateAuthTokens(user);
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate');
  }
};

/**
 * Reset password
 * @param {string} resetPasswordToken
 * @param {string} newPassword
 * @returns {Promise}
 */
const resetPassword = async (resetPasswordToken, newPassword) => {
  try {
    const resetPasswordTokenDoc = await tokenService.verifyToken(resetPasswordToken, tokenTypes.RESET_PASSWORD);
    const user = await userService.getUserById(resetPasswordTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await userService.updateUserById(user.id, { password: newPassword });
    await Token.deleteMany({ user: user.id, type: tokenTypes.RESET_PASSWORD });
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Password reset failed');
  }
};

/**
 * Verify email
 * @param {string} verifyEmailToken
 * @returns {Promise}
 */
const verifyEmail = async (verifyEmailToken) => {
  try {
    const verifyEmailTokenDoc = await tokenService.verifyToken(verifyEmailToken, tokenTypes.VERIFY_EMAIL);
    const user = await userService.getUserById(verifyEmailTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await Token.deleteMany({ user: user.id, type: tokenTypes.VERIFY_EMAIL });
    await userService.updateUserById(user.id, { isEmailVerified: true });
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Email verification failed');
  }
};

/**
 * Generate totp url
 * @param {User} user
 * @returns {Promise<Object>}
 */
const generateTotpUrl = async (user) => {
  try {
    if (!user) {
      throw new Error();
    }

    const key = Totp.generateKey({ issuer: config.mfa.issuer, user: user.email });

    return key;
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'MFA setup fail');
  }
};

/**
 * confirm totp url
 * @param {User} user
 * @returns {Promise}
 */
const confirmTotpUrl = async (user, mfaToken) => {
  try {
    if (!user) {
      throw new Error();
    }

    const isValid = Totp.validate({ passcode: mfaToken, secret: user.mfaTempSecret });

    if (isValid) {
      await userService.updateUserById(user.id, {
        mfaSecret: user.mfaTempSecret,
        mfaTempSecret: null,
      });
      // req.session.mfaTempSecret = null;  // 清除会话中的临时密钥
    } else {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid MFA token');
    }
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'MFA confirm fail');
  }
};

/**
 * check totp token
 * @param {User} user
 * @returns {Promise<User>}
 */
const checkTotp = async (user, mfaToken) => {
  try {
    if (!user) {
      throw new Error();
    }

    const isValid = Totp.validate({ passcode: mfaToken, secret: user.mfaSecret });

    if (isValid) {
      // 發另一個 jwt
      return user;
    } else {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid MFA token');
    }
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'MFA check fail');
  }
};

/**
 * confirm totp url
 * @param {User} user
 * @returns {Promise<string[]>}
 */
const generateAndSaveMfabackupCodes = async (user) => {
  try {
    if (!user) {
      throw new Error();
    }

    const backupCodes = generateBackupCodes();
    const hashedBackupCodes = Promise.all(backupCodes.map((backupCode) => bcrypt.hash(backupCode, 8)));

    await userService.updateUserById(user.id, {
      backupCodes: hashedBackupCodes,
    });

    return backupCodes;
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'backup codes setup fail');
  }
};

/**
 * confirm totp url
 * @param {User} user
 * @returns {Promise}
 */
const checkMfaBackupCode = async (user, backupCode) => {
  try {
    if (!user) {
      throw new Error();
    }

    const matchingCodeIndex = user.backupCodes.findIndex((hashedCode) => bcrypt.compareSync(backupCode, hashedCode));

    if (matchingCodeIndex === -1) {
      throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid backup code');
    }

    user.backupCodes.splice(matchingCodeIndex, 1);
    // await user.save();
    await userService.updateUserById(user.id, {
      backupCodes: user.backupCodes,
    });
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'backup code check fail');
  }
};

module.exports = {
  loginUserWithEmailAndPassword,
  logout,
  refreshAuth,
  resetPassword,
  verifyEmail,
  generateTotpUrl,
  confirmTotpUrl,
  checkTotp,
  generateAndSaveMfabackupCodes,
  checkMfaBackupCode,
};
