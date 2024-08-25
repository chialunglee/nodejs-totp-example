const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const { authService, userService, tokenService, emailService } = require('../services');

const register = catchAsync(async (req, res) => {
  const user = await userService.createUser(req.body);
  const tokens = await tokenService.generateAuthTokens(user);
  res.status(httpStatus.CREATED).send({ user, tokens });
});

const login = catchAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.loginUserWithEmailAndPassword(email, password);
  const shouldUseMfa = user.mfaSecret !== null;
  const tokens = shouldUseMfa ? await tokenService.generateVerifyMfaToken(user) : await tokenService.generateAuthTokens(user);

  res.send({
    user,
    tokens,
    shouldUseMfa,
  });
});

const logout = catchAsync(async (req, res) => {
  await authService.logout(req.body.refreshToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const refreshTokens = catchAsync(async (req, res) => {
  const tokens = await authService.refreshAuth(req.body.refreshToken);
  res.send({ ...tokens });
});

const forgotPassword = catchAsync(async (req, res) => {
  const resetPasswordToken = await tokenService.generateResetPasswordToken(req.body.email);
  await emailService.sendResetPasswordEmail(req.body.email, resetPasswordToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const resetPassword = catchAsync(async (req, res) => {
  await authService.resetPassword(req.query.token, req.body.password);
  res.status(httpStatus.NO_CONTENT).send();
});

const sendVerificationEmail = catchAsync(async (req, res) => {
  const verifyEmailToken = await tokenService.generateVerifyEmailToken(req.user);
  await emailService.sendVerificationEmail(req.user.email, verifyEmailToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token);
  res.status(httpStatus.NO_CONTENT).send();
});

const setupMfa = catchAsync(async (req, res) => {
  const time2faGenerateKey = await authService.generateTotpUrl(req.user);
  // TODO: 這個 mfaTempSecret 存很久
  await userService.updateUserById(req.user.id, { mfaTempSecret: time2faGenerateKey.secret });
  res.send({ totpUrl: time2faGenerateKey.url, manualSetupKey: time2faGenerateKey.secret });
});

const confirmMfa = catchAsync(async (req, res) => {
  await authService.confirmTotpUrl(req.user, req.body.mfaToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const removeMfa = catchAsync(async (req, res) => {
  await userService.updateUserById(req.user.id, { mfaTempSecret: null });
  res.status(httpStatus.NO_CONTENT).send();
});

const checkMfa = catchAsync(async (req, res) => {
  await authService.checkTotp(req.user, req.body.mfaToken);
  // 有執行到這邊，代表已通過檢查了，要不然早就已經 throw err 了
  const tokens = await tokenService.generateAuthTokens(req.user);
  // res.status(httpStatus.NO_CONTENT).send();
  res.send({
    user: req.user,
    tokens,
  });
});

const generateAndSaveMfabackupCodes = catchAsync(async (req, res) => {
  const backupCodes = await authService.generateAndSaveMfabackupCodes(req.user);
  res.send({ backupCodes });
});

const checkMfaBackupCode = catchAsync(async (req, res) => {
  await authService.checkMfaBackupCode(req.user, req.body.backupCode);
  // 有執行到這邊，代表已通過檢查了，要不然早就已經 throw err 了
  const tokens = await tokenService.generateAuthTokens(req.user);
  // res.status(httpStatus.NO_CONTENT).send();
  res.send({
    user: req.user,
    tokens,
  });
});

module.exports = {
  register,
  login,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
  setupMfa,
  confirmMfa,
  removeMfa,
  checkMfa,
  generateAndSaveMfabackupCodes,
  checkMfaBackupCode,
};
