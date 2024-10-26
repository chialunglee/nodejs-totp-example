module.exports = {
  testEnvironment: 'node',
  testEnvironmentOptions: {
    NODE_ENV: 'test',
  },
  restoreMocks: true,
  coveragePathIgnorePatterns: ['node_modules', 'src/config', 'src/app.js', 'tests'],
  coverageReporters: ['text', 'lcov', 'clover', 'html'],
  moduleNameMapper: {
    // time2fa 的 package.json 他的 main 寫 ./dist/index.mjs
    // 但是我的程式碼使用 require() ， jest 會抓錯，寫這行避免錯誤
    '^time2fa$': '<rootDir>/node_modules/time2fa/dist/index.cjs',
  },
};
