/**
 * Automated Security & Validation Test Suite
 * CS 477 - Homework 2-B
 */

const assert = require('assert');
const { validateLoginInput, authenticateUser, hashPassword, verifyPassword } = require('./server');

console.log('🧪 Starting Security & Validation Tests...\n');

let passedTests = 0;
let totalTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  ✅ PASS: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ FAIL: ${name}`);
    console.error(`     Reason: ${err.message}`);
  }
}

// 1. Validation Tests
runTest('Rejects empty submissions', () => {
  const result = validateLoginInput({ email: '', password: '' });
  assert.strictEqual(result.isValid, false);
  assert.ok(result.errors.email);
  assert.ok(result.errors.password);
});

runTest('Rejects email without @ symbol', () => {
  const result = validateLoginInput({ email: 'adminjuice.op', password: 'ValidPassword123' });
  assert.strictEqual(result.isValid, false);
  assert.ok(result.errors.email.includes('@'));
});

runTest('Rejects password shorter than 8 characters', () => {
  const result = validateLoginInput({ email: 'test@example.com', password: 'short' });
  assert.strictEqual(result.isValid, false);
  assert.ok(result.errors.password.includes('8 characters'));
});

runTest('Accepts valid credentials format', () => {
  const result = validateLoginInput({ email: 'student@example.com', password: 'SecurePassword2026!' });
  assert.strictEqual(result.isValid, true);
  assert.strictEqual(Object.keys(result.errors).length, 0);
});

// 2. SQL Injection Attack Scenarios
runTest('SQLi Attack Payload 1: Classic boolean bypass (\' OR 1=1 --)', () => {
  const sqliPayload = "' OR 1=1 --";
  const validation = validateLoginInput({ email: sqliPayload, password: 'password123' });
  // Validation should catch the malformed email format
  assert.strictEqual(validation.isValid, false);
  assert.ok(validation.errors.email);

  // Even if bypassed directly into authenticator, parameterized lookup must safely fail
  const auth = authenticateUser(sqliPayload, 'password123');
  assert.strictEqual(auth.success, false);
  assert.strictEqual(auth.message, 'Invalid email or password.');
});

runTest('SQLi Attack Payload 2: Targeted admin comment bypass (admin@juice-sh.op\' --)', () => {
  const sqliPayload = "admin@juice-sh.op' --";
  const auth = authenticateUser(sqliPayload, 'anything');
  // Parameterized lookup searches for exact string equality; will NOT match admin
  assert.strictEqual(auth.success, false);
  assert.strictEqual(auth.message, 'Invalid email or password.');
});

// 3. XSS Attack Scenarios
runTest('XSS Attack Payload 1: Injected <script> tag', () => {
  const xssPayload = "<script>alert('XSS')</script>@juice-sh.op";
  const auth = authenticateUser(xssPayload, 'Password123!');
  assert.strictEqual(auth.success, false);
});

// 4. Password Hashing & Verification
runTest('Password hashing produces secure salted output', () => {
  const pwd = 'MySecretPassword!';
  const { salt, hash } = hashPassword(pwd);
  assert.ok(salt.length >= 16);
  assert.ok(hash.length >= 64);
  assert.strictEqual(verifyPassword(pwd, salt, hash), true);
  assert.strictEqual(verifyPassword('WrongPassword!', salt, hash), false);
});

// 5. Valid Demo User Authentication
runTest('Authenticates legitimate demo user', () => {
  const auth = authenticateUser('admin@juice-sh.op', 'AdminPass123!');
  assert.strictEqual(auth.success, true);
  assert.strictEqual(auth.user.email, 'admin@juice-sh.op');
  assert.strictEqual(auth.user.role, 'administrator');
});

console.log(`\n=========================================`);
console.log(`Test Summary: ${passedTests}/${totalTests} tests passed.`);
console.log(`=========================================\n`);
