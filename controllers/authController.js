const db = require('../db');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fetch = require('node-fetch');


// ✅ Register function
exports.register = async (req, res) => {
  // Backend reCAPTCHA verification
  const recaptchaSecret = '6LdMtn4rAAAAAHFk8iQX4c8v1ZnlSBBGPVsLg2WQ';
  const recaptchaResponse = req.body['g-recaptcha-response'];
  if (!recaptchaResponse) {
    return res.send(`<script>alert('Please complete the reCAPTCHA.'); window.location.href='/signup/customer';</script>`);
  }
  try {
    const verifyRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${recaptchaSecret}&response=${recaptchaResponse}`
    });
    const verifyData = await verifyRes.json();
    if (!verifyData.success) {
      return res.send(`<script>alert('reCAPTCHA verification failed. Please try again.'); window.location.href='/signup/customer';</script>`);
    }
  } catch (e) {
    console.error('reCAPTCHA verification error:', e);
    return res.send(`<script>alert('reCAPTCHA verification error. Please try again.'); window.location.href='/signup/customer';</script>`);
  }

  // Map form fields to match DB columns
  const { full_name, nric, dob, email, phone, password, role } = req.body;
  const plainPassword = password;

  if (req.originalUrl === '/signup/staff') {
    if (role !== 'staff' && role !== 'financial_advisor') {
      return res.send(`<script>alert('Invalid role for staff sign up.'); window.location.href='/signup/staff';</script>`);
    }
  }

  // Check if user with this email exists
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err) {
      console.error("DB Select Error:", err);
      return res.send(`<script>alert('Registration failed. Please try again.'); window.location.href='/signup/${role}';</script>`);
    }
    if (users.length > 0) {
      const user = users[0];
      // If user is already fully registered (all required fields filled), show error
      if (user.full_name && user.nric && user.date_of_birth && user.phone_number && user.password && user.role) {
        return res.send(`<script>alert('Email already registered. Please login or use another email.'); window.location.href='/signup/${role}';</script>`);
      }
      // Otherwise, update the temp user row with real registration data
      const updateQuery = `UPDATE users SET full_name=?, nric=?, date_of_birth=?, phone_number=?, password=?, role=? WHERE email=?`;
      db.query(updateQuery, [full_name, nric, dob, phone, plainPassword, role, email], (updateErr) => {
        if (updateErr) {
          console.error("DB Update Error:", updateErr);
          return res.send(`<script>alert('Registration failed. Please try again.'); window.location.href='/signup/${role}';</script>`);
        }
        // Only now, after full registration, send welcome email if email_verified=1
        db.query('SELECT email_verified FROM users WHERE email = ?', [email], (verr, vres) => {
          if (verr || !vres.length) {
            return res.send(`<script>alert('Registration failed. Please try again.'); window.location.href='/signup/${role}';</script>`);
          }
          // Only render the success page; welcome email is sent after OTP verification only
          if (role === 'staff' || role === 'financial_advisor') {
            res.render('staff-signup-success');
          } else {
            res.render('signup-success');
          }
        });
      });
    } else {
      // No user exists, insert as usual
      const insertQuery = `INSERT INTO users (full_name, nric, date_of_birth, email, phone_number, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)`;
      db.query(insertQuery, [full_name, nric, dob, email, phone, plainPassword, role], (err2, result) => {
        if (err2) {
          console.error("DB Insert Error:", err2);
          return res.send(`<script>alert('Registration failed. Please try again.'); window.location.href='/signup/${role}';</script>`);
        }
        // Only now, after full registration, send welcome email if email_verified=1
        db.query('SELECT email_verified FROM users WHERE user_id = ?', [result.insertId], (verr, vres) => {
          if (verr || !vres.length) {
            return res.send(`<script>alert('Registration failed. Please try again.'); window.location.href='/signup/${role}';</script>`);
          }
          if (vres[0].email_verified === 1) {
            const transporter = nodemailer.createTransport({
              service: 'gmail',
              auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
              tls: { rejectUnauthorized: false }
            });
            const mailOptions = {
              from: process.env.EMAIL_USER,
              to: email,
              subject: 'Welcome to HoH Bank!',
              html: `<h2>Welcome to HoH Bank!</h2><p>Your account has been successfully created and your email is verified. Enjoy our services!</p>`
            };
            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error('Welcome email send error:', error);
              } else {
                console.log('Welcome email sent:', info.response);
              }
              if (role === 'staff' || role === 'financial_advisor') {
                res.render('staff-signup-success');
              } else {
                res.render('signup-success');
              }
            });
          } else {
            if (role === 'staff' || role === 'financial_advisor') {
              res.render('staff-signup-success');
            } else {
              res.render('signup-success');
            }
          }
        });
      });
    }
  });
};

// ✅ Login function
exports.login = (req, res) => {
  if (req.originalUrl === '/login/staff') {
    // ...existing staff login code...
    const { email, password, role } = req.body;
    const query = `SELECT * FROM users WHERE email = ?`;
    db.query(query, [email], async (err, results) => {
      if (err) {
        console.error("DB error:", err);
        return res.status(500).render('staff-login', { error: 'Internal server error. Please try again.' });
      }
      if (results.length === 0) {
        // Email not found
        return res.render('staff-login', { error: 'Email incorrect.' });
      }
      const user = results[0];
      if (user.role !== role) {
        // Wrong role
        return res.render('staff-login', { error: 'Role not allowed. Please use the correct login page.' });
      }
      if (password !== user.password) {
        // Wrong password
        return res.render('staff-login', { error: 'Incorrect password.' });
      }
      if (user.enable_2fa) {
        // Generate OTP and send email
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60000); // 10 min expiry
        db.query('INSERT INTO otp_requests (user_id, purpose, otp_code, expires_at) VALUES (?, ?, ?, ?)', [user.user_id, 'login_2fa', otp, expiresAt], (err2) => {
          if (err2) {
            return res.render('staff-login', { error: 'Failed to generate OTP. Try again.' });
          }
          // Send OTP email
          const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
            tls: { rejectUnauthorized: false }
          });
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'HoH Bank Login OTP',
            html: `<h3>Your OTP for login is: <b>${otp}</b></h3><p>This OTP will expire in 10 minutes.</p>`
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error('Nodemailer error:', error);
              return res.render('staff-login', { error: 'Failed to send OTP email. Try again.' });
            }
            req.session.pending_2fa_user = user;
            // Do NOT set req.session.user here!
            res.redirect(`/verify-otp-2fa?email=${encodeURIComponent(user.email)}`);
          });
        });      } else {
        req.session.user = user;
        // Redirect based on role
        if (user.role === 'financial_advisor') {
          return res.redirect('/advisor/dashboard');
        } else {
          return res.redirect('/dashboard/staff');
        }
      }
    });
    return;
  }
  // Customer login logic
  if (req.originalUrl === '/login/customer') {
    const { email, password } = req.body;
    const query = `SELECT * FROM users WHERE email = ?`;
    db.query(query, [email], async (err, results) => {
      if (err) {
        console.error("DB error:", err);
        return res.status(500).render('customer-login', { error: 'Internal server error. Please try again.' });
      }
      if (results.length === 0) {
        // Email not found
        return res.render('customer-login', { error: 'Email incorrect.' });
      }
      const user = results[0];
      if (user.role !== 'customer') {
        // Not a customer
        return res.render('customer-login', { error: 'Role not allowed. Please use the correct login page.' });
      }
      if (password !== user.password) {
        // Wrong password
        return res.render('customer-login', { error: 'Incorrect password.' });
      }
      // 2FA check for customer
      if (user.enable_2fa) {
        // Generate OTP and send email
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60000); // 10 min expiry
        db.query('INSERT INTO otp_requests (user_id, purpose, otp_code, expires_at) VALUES (?, ?, ?, ?)', [user.user_id, 'login_2fa', otp, expiresAt], (err2) => {
          if (err2) {
            return res.render('customer-login', { error: 'Failed to generate OTP. Try again.' });
          }
          // Send OTP email
          const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
            tls: { rejectUnauthorized: false }
          });
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'HoH Bank Login OTP',
            html: `<h3>Your OTP for login is: <b>${otp}</b></h3><p>This OTP will expire in 10 minutes.</p>`
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error('Nodemailer error:', error);
              return res.render('customer-login', { error: 'Failed to send OTP email. Try again.' });
            }
            req.session.pending_2fa_user = user;
            // Do NOT set req.session.user here!
            res.redirect(`/verify-otp-2fa?email=${encodeURIComponent(user.email)}`);
          });
        });
      } else {
        // Successful login without 2FA
        req.session.user = user;
        return res.redirect('/dashboard');
      }
    });
    return;
  }
};

// 2FA OTP verification for login
exports.verifyOtp2fa = (req, res) => {
  const { email, otp } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err || users.length === 0) {
      return res.send('<script>alert("Invalid email."); window.location.href="/login/customer";</script>');
    }
    const user = users[0];
    db.query('SELECT * FROM otp_requests WHERE user_id = ? AND purpose = ? AND otp_code = ? AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
      [user.user_id, 'login_2fa', otp], (err2, otps) => {
      if (err2 || otps.length === 0) {
        return res.send('<script>alert("Invalid or expired OTP."); window.location.href="/verify-otp-2fa?email='+encodeURIComponent(email)+'";</script>');
      }      // OTP is valid, log in user
      req.session.user = user;
      delete req.session.pending_2fa_user;
      // Clean up OTP
      db.query('DELETE FROM otp_requests WHERE otp_id = ?', [otps[0].otp_id]);
      if (user.role === 'staff') {
        return res.redirect('/dashboard/staff');
      } else if (user.role === 'financial_advisor') {
        return res.redirect('/advisor/dashboard');
      } else {
        return res.redirect('/dashboard');
      }
    });
  });
};

// Password reset request (step 1: send OTP)
exports.requestPasswordReset = (req, res) => {
  const { email } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err || results.length === 0) {
      return res.send('<script>alert("No user found with that email."); window.location.href="/reset-password";</script>');
    }
    const user = results[0];
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60000); // 10 minutes from now
    db.query('INSERT INTO otp_requests (user_id, purpose, otp_code, expires_at) VALUES (?, ?, ?, ?)', [user.user_id, 'password_reset', otp, expiresAt], (err2) => {
      if (err2) {
        return res.send('<script>alert("Failed to generate OTP. Try again."); window.location.href="/reset-password";</script>');
      }
      // Send OTP email
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        tls: { rejectUnauthorized: false }
      });
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'HoH Bank Password Reset OTP',
        html: `<h3>Your OTP for password reset is: <b>${otp}</b></h3><p>This OTP will expire in 10 minutes.</p>`
      };
      console.log('Attempting to send OTP to:', email, 'OTP:', otp);
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Nodemailer error:', error);
          return res.send('<script>alert("Failed to send OTP email. Try again."); window.location.href="/reset-password";</script>');
        }
        console.log('OTP email sent:', info.response);
        res.redirect(`/verify-otp?email=${encodeURIComponent(email)}`);
      });
    });
  });
};

// OTP verification (step 2) - now handles both password reset and signup email verification
exports.verifyOtp = (req, res) => {
  const { email, otp } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err || users.length === 0) {
      return res.send('<script>alert("Invalid email."); window.location.href="/reset-password";</script>');
    }
    const user = users[0];
    // Check for signup email verification OTP first
    db.query('SELECT * FROM otp_requests WHERE user_id = ? AND purpose = ? AND otp_code = ? AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
      [user.user_id, 'signup_email_verification', otp], (err2, otps) => {
      if (!err2 && otps.length > 0) {
        // OTP is valid for signup email verification
        db.query('UPDATE users SET email_verified = 1 WHERE user_id = ?', [user.user_id], (uerr) => {
          if (uerr) {
            return res.send('<script>alert("Failed to verify email. Try again."); window.location.href="/verify-otp?email='+encodeURIComponent(email)+'";</script>');
          }
          // Clean up OTP
          db.query('DELETE FROM otp_requests WHERE otp_id = ?', [otps[0].otp_id]);
          // Send welcome email
          const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
            tls: { rejectUnauthorized: false }
          });
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Welcome to HoH Bank – Your Account is Ready!',
            html: `<h2>Welcome to HoH Bank! 🎉</h2>
<p>Dear Valued Customer,</p>
<p>We are pleased to inform you that your account has been successfully created and your email address has been verified. <span style="font-size:1.2em;">✅</span></p>
<p>You can now log in and enjoy secure access to our full suite of digital banking services, including account management, fund transfers, and financial tools designed to help you achieve your goals. 🏦</p>
<p>If you have any questions or need assistance, our support team is here to help at any time. 😊</p>
<p>Thank you for choosing HoH Bank as your trusted financial partner.</p>
<br>
<p>Best regards,<br>HoH Bank Team</p>`
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error('Welcome email send error:', error);
            } else {
              console.log('Welcome email sent to user:', email, info.response);
            }
            res.render('signup-success');
          });
        });
        return;
      }
      // Otherwise, check for password reset OTP
      db.query('SELECT * FROM otp_requests WHERE user_id = ? AND purpose = ? AND otp_code = ? AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
        [user.user_id, 'password_reset', otp], (err3, otps2) => {
        if (err3 || otps2.length === 0) {
          return res.send('<script>alert("Invalid or expired OTP."); window.location.href="/verify-otp?email='+encodeURIComponent(email)+'";</script>');
        }
        // OTP is valid, set session flag and show set new password page
        req.session.password_reset_verified = email;
        res.render('set-new-password', { email });
      });
    });
  });
};

// Set new password (step 3)
exports.setNewPassword = (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.send('<script>alert("Missing email or password."); window.location.href="/reset-password";</script>');
  }
  // Enforce OTP verification before allowing password reset
  if (!req.session.password_reset_verified || req.session.password_reset_verified !== email) {
    return res.send('<script>alert("You must verify OTP before resetting your password."); window.location.href="/reset-password";</script>');
  }
  // Find user
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err || users.length === 0) {
      return res.send('<script>alert("Invalid email."); window.location.href="/reset-password";</script>');
    }
    // Update password
    db.query('UPDATE users SET password = ? WHERE email = ?', [password, email], (err2) => {
      if (err2) {
        return res.send('<script>alert("Failed to update password. Try again."); window.location.href="/reset-password";</script>');
      }
      // Optionally: clean up OTPs for this user
      db.query('DELETE FROM otp_requests WHERE user_id = ? AND purpose = ?', [users[0].user_id, 'password_reset'], () => {
        // Ignore errors here
        // Clear session flag after successful reset
        req.session.password_reset_verified = null;
        res.render('password-reset-success');
      });
    });
  });
};

// Change Password with OTP (step 1: send OTP)
exports.requestChangePasswordOtp = (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const user = req.session.user;
  const { currentPassword, newPassword, confirmPassword } = req.body;
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.render('change-password', { message: 'All fields are required.' });
  }
  if (newPassword !== confirmPassword) {
    return res.render('change-password', { message: 'New passwords do not match.' });
  }
  // Check current password
  db.query('SELECT password FROM users WHERE user_id = ?', [user.user_id], (err, results) => {
    if (err || results.length === 0) {
      return res.render('change-password', { message: 'User not found.' });
    }
    // Compare plain password
    if (currentPassword !== results[0].password) {
      return res.render('change-password', { message: 'Current password is incorrect.' });
    }
    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60000); // 10 min expiry
    db.query('INSERT INTO otp_requests (user_id, purpose, otp_code, expires_at) VALUES (?, ?, ?, ?)', [user.user_id, 'change_password', otp, expiresAt], (err2) => {
      if (err2) {
        return res.render('change-password', { message: 'Failed to generate OTP. Try again.' });
      }
      // Send OTP email
      const transporter = require('nodemailer').createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        tls: { rejectUnauthorized: false }
      });
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'HoH Bank Change Password OTP',
        html: `<h3>Your OTP for changing password is: <b>${otp}</b></h3><p>This OTP will expire in 10 minutes.</p>`
      };
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Nodemailer error:', error);
          return res.render('change-password', { message: 'Failed to send OTP email. Try again.' });
        }
        // Store new password in session temporarily for verification step
        req.session.change_password_pending = { user_id: user.user_id, newPassword };
        res.redirect('/verify-otp-change-password');
      });
    });
  });
};

// Change Password with OTP (step 2: verify OTP and update password)
exports.verifyOtpChangePassword = (req, res) => {
  if (!req.session.user || !req.session.change_password_pending) return res.redirect('/login/customer');
  const { otp } = req.body;
  const { user_id, newPassword } = req.session.change_password_pending;
  db.query('SELECT * FROM otp_requests WHERE user_id = ? AND purpose = ? AND otp_code = ? AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
    [user_id, 'change_password', otp], (err, otps) => {
    if (err || otps.length === 0) {
      return res.render('verify-otp-change-password', { email: req.session.user.email, message: 'Invalid or expired OTP.' });
    }
    // OTP is valid, update password
    db.query('UPDATE users SET password = ? WHERE user_id = ?', [newPassword, user_id], (err2) => {
      if (err2) {
        return res.render('verify-otp-change-password', { email: req.session.user.email, message: 'Failed to update password. Try again.' });
      }
      // Clean up OTP and session
      db.query('DELETE FROM otp_requests WHERE otp_id = ?', [otps[0].otp_id]);
      req.session.destroy(() => {
        res.render('password-reset-success');
      });
    });
  });
};
