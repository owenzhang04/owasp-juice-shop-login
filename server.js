/**
 * OWASP Juice Shop - Secure Login Server
 * CS 477 - Homework 2-B
 * 
 * Features:
 * - Serves frontend static assets (HTML, CSS, JS)
 * - Strict server-side input validation (empty check, email format, password length >= 8)
 * - Parameterized mock database lookup (resilient to SQL Injection)
 * - Cryptographic password hashing with salt (scrypt/PBKDF2/bcrypt design)
 * - Defense against Cross-Site Scripting (CSP headers, no reflected sinks)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

/**
 * Utility: Securely hash a password using Node's cryptographic scrypt KDF.
 * Follows OWASP recommendations for salted password storage.
 */
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return {
    salt,
    hash: derivedKey.toString('hex')
  };
}

/**
 * Utility: Verify a password against stored salt and hash using timing-safe comparison.
 */
function verifyPassword(password, salt, storedHash) {
  const derivedKey = crypto.scryptSync(password, salt, 64);
  const keyBuffer = Buffer.from(derivedKey.toString('hex'), 'hex');
  const storedBuffer = Buffer.from(storedHash, 'hex');
  if (keyBuffer.length !== storedBuffer.length) return false;
  return crypto.timingSafeEqual(keyBuffer, storedBuffer);
}

// Pre-populate mock database with secure salted hashes
// Demo user: admin@juice-sh.op / AdminPass123!
const adminHash = hashPassword('AdminPass123!', 'fixed_salt_juice_shop_demo');
const mockUserDatabase = [
  {
    id: 1,
    email: 'admin@juice-sh.op',
    salt: adminHash.salt,
    passwordHash: adminHash.hash,
    role: 'administrator'
  },
  {
    id: 2,
    email: 'user@juice-sh.op',
    salt: hashPassword('RegularUser2026!').salt,
    passwordHash: hashPassword('RegularUser2026!').hash,
    role: 'customer'
  }
];

/**
 * Server-Side Validation:
 * Never trust client-side validation alone; validate every field on the backend.
 */
function validateLoginInput(body) {
  const errors = {};
  const email = (body && typeof body.email === 'string') ? body.email.trim() : '';
  const password = (body && typeof body.password === 'string') ? body.password : '';

  // 1. Check for empty fields
  if (!email) {
    errors.email = 'Server validation: Email cannot be empty.';
  } else if (!email.includes('@')) {
    // 2. Check for '@' symbol
    errors.email = 'Server validation: Email must contain an "@" symbol.';
  } else {
    // Basic RFC 5322 regex validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      errors.email = 'Server validation: Please provide a valid email format (e.g., name@domain.com).';
    }
  }

  // 3. Password empty and length check (min 8 chars)
  if (!password) {
    errors.password = 'Server validation: Password cannot be empty.';
  } else if (password.length < 8) {
    errors.password = 'Server validation: Password must be at least 8 characters long.';
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
    sanitized: { email, password }
  };
}

/**
 * Secure Authentication Logic:
 * Uses parameterized comparison (exact lookup by key) to prevent SQL Injection.
 */
function authenticateUser(email, password) {
  // Equivalent to: SELECT * FROM Users WHERE email = ? (Parameterized query)
  const normalizedEmail = email.toLowerCase();
  const user = mockUserDatabase.find(u => u.email.toLowerCase() === normalizedEmail);

  if (!user) {
    // User not found (generic error to prevent account enumeration)
    return { success: false, message: 'Invalid email or password.' };
  }

  const isPasswordValid = verifyPassword(password, user.salt, user.passwordHash);
  if (!isPasswordValid) {
    return { success: false, message: 'Invalid email or password.' };
  }

  return {
    success: true,
    user: { id: user.id, email: user.email, role: user.role }
  };
}

// Request Handler
const server = http.createServer((req, res) => {
  // Set OWASP Recommended Security Headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");

  const url = new URL(req.url, `http://${req.headers.host}`);

  // API Route: POST /api/login
  if (req.method === 'POST' && url.pathname === '/api/login') {
    let bodyData = '';
    req.on('data', chunk => {
      bodyData += chunk;
      // Guard against payload flooding (max 10KB)
      if (bodyData.length > 10 * 1024) {
        req.destroy();
      }
    });

    req.on('end', () => {
      let parsedBody;
      try {
        parsedBody = JSON.parse(bodyData);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: false,
          message: 'Malformed JSON payload.'
        }));
      }

      console.log(`[AUTH ATTEMPT] Timestamp: ${new Date().toISOString()} | Input Email: ${JSON.stringify(parsedBody.email)}`);

      // 1. Execute Server-Side Validation
      const validation = validateLoginInput(parsedBody);
      if (!validation.isValid) {
        console.log(`[VALIDATION REJECTED] Errors:`, validation.errors);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: false,
          message: 'Server-side validation failed.',
          errors: validation.errors
        }));
      }

      // 2. Perform Authentication
      const authResult = authenticateUser(validation.sanitized.email, validation.sanitized.password);
      if (authResult.success) {
        console.log(`[AUTH SUCCESS] User logged in: ${authResult.user.email} (${authResult.user.role})`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: true,
          message: 'Login successful!',
          user: authResult.user
        }));
      } else {
        console.log(`[AUTH FAILURE] Invalid credentials for: ${validation.sanitized.email}`);
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          success: false,
          message: authResult.message
        }));
      }
    });
    return;
  }

  // Static File Serving
  if (req.method === 'GET') {
    let safePath = url.pathname === '/' ? '/index.html' : url.pathname;
    const filePath = path.join(PUBLIC_DIR, safePath);

    // Guard against directory traversal
    if (!filePath.startsWith(PUBLIC_DIR)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('Access Denied');
    }

    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.png': 'image/png',
      '.svg': 'image/svg+xml'
    };

    const ext = path.extname(filePath);
    const contentType = mimeTypes[ext] || 'text/plain';

    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        return res.end('404 Not Found');
      }
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(data);
    });
    return;
  }

  res.writeHead(405, { 'Content-Type': 'text/plain' });
  res.end('Method Not Allowed');
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(` OWASP Juice Shop Secure Login Mockup Server`);
    console.log(` Server running at http://localhost:${PORT}`);
    console.log(` Static directory: ${PUBLIC_DIR}`);
    console.log(` Demo Account: admin@juice-sh.op / AdminPass123!`);
    console.log(`====================================================`);
  });
}

module.exports = { server, validateLoginInput, authenticateUser, hashPassword, verifyPassword };
