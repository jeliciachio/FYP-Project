const express = require('express');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser');
require('dotenv').config();

const crypto = require('crypto');
const nodemailer = require('nodemailer');
const multer = require('multer');
const { Parser } = require('json2csv');
const dialogflow = require('dialogflow');
const uuid = require('uuid');
const otpMap = new Map(); // In-memory OTP storage for email OTPs
// ✅ Insert this directly below 👇
function setRole(role) {
  return (req, res, next) => {
    req.body.role = role;
    next();
  };
}


const mysql = require('mysql'); 

const app = express();
const PORT = process.env.PORT || 3000;


const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/images'); // Make sure this folder exists or create it
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),

});

const upload = multer({ storage: storage });


const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

const sessionSecret = process.env.SESSION_SECRET;

const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID
};

firebase.initializeApp(firebaseConfig);


// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use('/public', express.static('public'));
app.use('/images', express.static(path.join(__dirname, 'public/images')));
app.use(express.json());


app.use(session({
    secret: 'rp_digital_bank_secret',
    resave: false,
    saveUninitialized: true
}));

// ✅ Profile route goes BELOW session
app.get('/profile', (req, res) => {
  console.log('DEBUG /profile req.session.user:', req.session.user);
  if (!req.session.user) return res.redirect('/login/customer');
  console.log('✅ Rendering profile-edit.ejs');
  res.render('profile-edit', { user: req.session.user, message: null });
});
// Customer Profile Edit Page (GET)
app.get('/profile-edit', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  res.render('profile-edit', { user: req.session.user, message: null });
});



// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const authController = require('./controllers/authController'); // keep this for login/signup

// Static Pages
app.get('/', (req, res) => {
  db.query('SELECT * FROM product_catalog', (err, products) => {
    if (err) {
      console.error('DB error:', err);
      return res.render('index', { products: [] });
    }
    res.render('index', { products });
  });
});
app.get('/terms', (req, res) => res.render('terms'));
app.get('/conditions', (req, res) => res.render('conditions_of_access'));
app.get('/notices', (req, res) => res.render('notices'));

// Customer Login & Signup
app.get('/login/customer', (req, res) => res.render('customer-login'));
app.get('/signup/customer', (req, res) => {
  res.render('customer-signup', {
    myinfo: null,
    firebasePublic: {
      apiKey: process.env.FIREBASE_API_KEY,
      authDomain: process.env.FIREBASE_AUTH_DOMAIN,
      projectId: process.env.FIREBASE_PROJECT_ID,
      messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
      appId: process.env.FIREBASE_APP_ID,
      measurementId: process.env.FIREBASE_MEASUREMENT_ID
    }
  });
});
app.post('/signup/customer', (req, res) =>
  authController.register({ ...req, body: { ...req.body, role: 'customer' } }, res)
);
app.post('/login/customer', (req, res) =>
  authController.login({ ...req, body: { ...req.body, role: 'customer' } }, res)
);

// Advisor Login & Signup
app.get('/login/advisor', (req, res) => res.redirect('/login/staff'));
app.get('/signup/advisor', (req, res) => res.render('advisor-signup'));
app.post('/signup/advisor', (req, res) =>
  authController.register({ ...req, body: { ...req.body, role: 'financial_advisor' } }, res)
);
app.post('/login/advisor', (req, res) =>
  authController.login({ ...req, body: { ...req.body, role: 'financial_advisor' } }, res)
);

// Staff Login & Signup
app.get('/login/staff', (req, res) => res.render('staff-login'));
app.get('/signup/staff', (req, res) => res.render('staff-signup'));
app.post('/signup/staff', (req, res) =>
  authController.register({ ...req, body: { ...req.body, role: 'staff' } }, res)
);
app.post('/login/staff', (req, res) => {
  authController.login(req, res);
});

//Cancel Account Page (GET)
app.get('/cancel-account/:accountNumber', (req, res) => {
  const accountNumber = req.params.accountNumber;
  const sql = `SELECT * FROM accounts WHERE account_number = ?`;

  db.query(sql, [accountNumber], (err, results) => {
    if (err) {
      console.error('❌ DB error:', err);
      return res.status(500).send('Database error.');
    }

    if (results.length === 0) {
      return res.status(404).send('Account not found.');
    }

    const account = results[0];

    res.render('cancel-account-page', {
      accountNumber,
      error: null,
      success: null,
      otpSent: false,
      balance: account.balance
    });
  });
});


//Staff Account Approval View
app.get('/staff/accounts', async (req, res) => {
  try {
    const [pendingAccounts] = await db.promise().query(`
      SELECT * FROM account_applications 
      WHERE status = 'pending'
    `);
    const [approvedAccounts] = await db.promise().query(`
      SELECT * FROM account_applications 
      WHERE status = 'approved'
    `);
    const [rejectedAccounts] = await db.promise().query(`
      SELECT * FROM account_applications 
      WHERE status = 'rejected'
    `);

    res.render('staff-accounts-application', {
      pendingAccounts,
      approvedAccounts,
      rejectedAccounts
    });
  } catch (err) {
    console.error('Error loading staff accounts:', err);
    res.status(500).send("Server error");
  }
});


//Staff Action (Approve/Reject) on Account Applications
app.post('/staff/account/action', (req, res) => {
  const { application_id, action, rejection_reason } = req.body;

  if (!['accept', 'reject'].includes(action)) return res.redirect('/staff/accounts');

  const getAppQuery = `SELECT * FROM account_applications WHERE application_id = ?`;

  db.query(getAppQuery, [application_id], (err, results) => {
    if (err || results.length === 0) return res.status(404).send("Application not found");
    const app = results[0];

    const newStatus = action === 'accept' ? 'approved' : 'rejected';

    const updateQuery = `UPDATE account_applications SET status = ?, kyc_verified = 1 WHERE application_id = ?`;

    db.query(updateQuery, [newStatus, application_id], (err2) => {
      if (err2) return res.status(500).send("Failed to update application");

      if (action === 'accept') {
        const accountNumber = generateRandomNumber(9);
        const insertAccount = `
          INSERT INTO accounts (user_id, product_id, full_name, account_number, account_type, balance, account_status)
          VALUES (?, ?, ?, ?, ?, 0.00, 'active')
        `;
        db.query(insertAccount, [
          app.user_id, app.product_id, app.full_name, accountNumber, app.account_type
        ], (err3) => {
          if (err3) return res.status(500).send("Failed to create account");

          sendConfirmationEmailStatus(app.email, app.full_name, app.account_type, 'Approved', accountNumber)
            .then(() => res.redirect('/staff/accounts'))
            .catch(() => res.redirect('/staff/accounts'));
        });
      } else {
        sendConfirmationEmailStatus(app.email, app.full_name, app.account_type, 'Rejected')
          .then(() => res.redirect('/staff/accounts'))
          .catch(() => res.redirect('/staff/accounts'));
      }
    });
  });
});

//jeli----------------------------------------------------------------
// Staff Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).send("Logout failed");
    }
    res.redirect('/login/staff'); // Redirect to staff login page
  });
});

// --- Staff Dashboard Logic (Jeli) ---
async function renderStaffDashboard(req, res) {
  const staffId = req.session.staffId;
  if (!staffId) return res.redirect('/login/staff');

  const selectedYear = req.query.year || '2025';
  const selectedMonth = req.query.month || '1';

  try {
    const [rows] = await db.promise().query('SELECT * FROM users WHERE user_id = ?', [staffId]);
    if (rows.length === 0) return res.status(404).send('Staff not found.');
    const staff = rows[0];

    const [[accountsOpenedResult]] = await db.promise().query(
      `SELECT COUNT(*) AS count FROM accounts WHERE MONTH(created_at) = ? AND YEAR(created_at) = ?`,
      [selectedMonth, selectedYear]
    );

    const [[pendingFormsResult]] = await db.promise().query(
      `SELECT COUNT(*) AS count FROM card_applications WHERE status = 'pending'`
    );

    const [[consultationsResult]] = await db.promise().query(
      `SELECT COUNT(*) AS count FROM consultations WHERE MONTH(appointment_date) = ? AND YEAR(appointment_date) = ?`,
      [selectedMonth, selectedYear]
    );

    const [accountTypeCounts] = await db.promise().query(
      `SELECT account_type, COUNT(*) AS total FROM accounts GROUP BY account_type`
    );

    const [[totalTransactionsResult]] = await db.promise().query(
      `SELECT COUNT(*) AS count FROM transactions WHERE MONTH(transaction_date) = ? AND YEAR(transaction_date) = ?`,
      [selectedMonth, selectedYear]
    );

    const [consultationEvents] = await db.promise().query(`
      SELECT 
        c.appointment_date AS start,
        CONCAT('Advisor: ', u.full_name) AS title
      FROM consultations c
      JOIN users u ON c.advisor_id = u.user_id
      WHERE u.role = 'financial_advisor'
    `);

    const [[pendingCount]] = await db.promise().query(
      `SELECT COUNT(*) AS count FROM card_applications WHERE status = 'pending'`
    );
    const [[approvedCount]] = await db.promise().query(
      `SELECT COUNT(*) AS count FROM card_applications WHERE status = 'approved'`
    );
    const [[rejectedCount]] = await db.promise().query(
      `SELECT COUNT(*) AS count FROM card_applications WHERE status = 'rejected'`
    );

    const accountTypes = {
      savings: 0,
      fixedDeposit: 0,
      creditCard: 0,
      debitCard: 0
    };

    accountTypeCounts.forEach(row => {
      switch (row.account_type.toLowerCase()) {
        case 'savings':
          accountTypes.savings = row.total;
          break;
        case 'fixed_deposit':
        case 'fixeddeposit':
          accountTypes.fixedDeposit = row.total;
          break;
        // If credit/debit cards are in cards table, leave at 0
      }
    });

    const totalAccounts = accountTypeCounts.reduce((sum, row) => sum + row.total, 0);

    const stats = {
      accountsOpened: accountsOpenedResult.count,
      pendingForms: pendingFormsResult.count,
      consultations: consultationsResult.count,
      accountTypeCounts,
      accountTypes,
      totalAccounts,
      totalTransactions: totalTransactionsResult.count,
      statusCounts: {
        pending: pendingCount.count,
        approved: approvedCount.count,
        rejected: rejectedCount.count
      }
    };

    const [consultationDetails] = await db.promise().query(`
      SELECT 
        c.appointment_date,
        TIME_FORMAT(c.appointment_date, '%H:%i') AS appointment_time,
        a.full_name AS advisor_name,
        s.full_name AS customer_name,
        c.notes
      FROM consultations c
      LEFT JOIN users a ON c.advisor_id = a.user_id
      LEFT JOIN users s ON c.customer_id = s.user_id
      WHERE c.status = 'accepted'
      ORDER BY c.appointment_date DESC
    `);

    res.render('staff-dashboard', {
      staff,
      stats,
      selectedYear,
      selectedMonth,
      consultationEvents,
      consultationDetails
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).send('Error loading dashboard');
  }
}

// --- User Management Logic ---
async function viewAllUsers(req, res) {
  const staffId = req.session.staffId;
  if (!staffId) return res.redirect('/login/staff');
  const searchQuery = req.query.search || '';
  let query = 'SELECT * FROM users';
  let params = [];

  if (searchQuery) {
    query += ` WHERE full_name LIKE ? OR email LIKE ? OR role LIKE ?`;
    const likeQuery = `%${searchQuery}%`;
    params = [likeQuery, likeQuery, likeQuery];
  }

  try {
    const [rows] = await db.promise().query(query, params);
    res.render('staff-user-management', { users: rows, searchQuery });
  } catch (err) {
    console.error('User list error:', err);
    res.status(500).send('Error retrieving users');
  }
}

//Product Catalog CRUD Logic
async function addProduct(req, res) {
  const { product_name, product_type, description } = req.body;
  try {
    await db.promise().query(
      'INSERT INTO product_catalog (product_name, product_type, description) VALUES (?, ?, ?)',
      [product_name, product_type, description]
    );
    res.redirect('/admin/products');
  } catch (err) {
    console.error('Error adding product:', err);
    res.status(500).send('Internal Server Error');
  }
}

async function editProduct(req, res) {
  const { product_name, product_type, description } = req.body;
  const productId = req.params.id;

  try {
    await db.promise().query(
      'UPDATE product_catalog SET product_name = ?, product_type = ?, description = ? WHERE product_id = ?',
      [product_name, product_type, description, productId]
    );
    res.redirect('/admin/products');
  } catch (err) {
    console.error('Error editing product:', err);
    res.status(500).send('Internal Server Error');
  }
}

async function deleteProduct(req, res) {
  const productId = req.params.id;
  try {
    await db.promise().query('DELETE FROM product_catalog WHERE product_id = ?', [productId]);
    res.redirect('/admin/products');
  } catch (err) {
    console.error('Error deleting product:', err);
    res.status(500).send('Internal Server Error');
  }
}

// Staff Dashboard and User Management Routes
app.get('/admin/dashboard', renderStaffDashboard);

app.get('/admin/users', viewAllUsers);

app.get('/staff/users', async (req, res) => {
  const [users] = await db.promise().query(`SELECT * FROM users`);
  res.render('staff-user-management', { users });
});

// Keep existing routes but redirect to /product-catalog
app.get('/admin/products', async (req, res) => {
  res.redirect('/product-catalog');
});

app.post('/admin/products', addProduct);
app.post('/admin/products/:id/edit', editProduct);
app.post('/admin/products/:id/delete', deleteProduct);
app.post('/submit-savings-account', upload.single('photo'), (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');

  const user = req.session.user;
  // Step 1: Check for existing pending/approved savings application
  const checkSql = `
    SELECT * FROM account_applications
    WHERE user_id = ? AND account_type = 'savings' AND status IN ('pending', 'approved')
  `;

  db.query(checkSql, [user.user_id], (checkErr, existingApps) => {
    if (checkErr) {
      console.error('❌ DB error during savings app check:', checkErr);
      return res.status(500).send('Database error while checking existing applications.');
    }

    if (existingApps.length > 0) {
      return res.send(`
        <script>
          alert("A pending application is currently under review for this product. Please wait for an email update from HOH Bank before applying again.");
          window.location.href = "/my-products";
        </script>
      `);
    }
    // Step 2: Proceed with application submission

    const {
      nationality = '',
      income_source = 0.00,
      address = ''
    } = req.body;

    const student_id_upload_path = req.file ? req.file.path : '';
    const dob = new Date(user.date_of_birth).toISOString().split('T')[0];
    const productId = 3; // savings product ID

    const query = `
      INSERT INTO account_applications (
        user_id, product_id, full_name, email, phone_number, date_of_birth, nric,
        nationality, income_source, address, student_id_upload_path,
        account_type, status, kyc_verified, submitted_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'savings', 'pending', false, NOW())
    `;

    const values = [
      user.user_id, productId, user.full_name, user.email, user.phone_number, dob, user.nric,
      nationality, income_source, address, student_id_upload_path
    ];

    db.query(query, values, (err, result) => {
      if (err) {
        console.error('❌ Insert error (Savings):', err);
        return res.status(500).send('Failed to submit application.');
      }

      sendConfirmationEmailStatus(user.email, user.full_name, 'Savings Account', 'Pending')
        .then(() => {
          res.render('process-confirmation', {
            application: {
              full_name: user.full_name,
              email: user.email,
              phone_number: user.phone_number,
              card_type: 'Savings Account',
              status: 'pending',
              application_id: result.insertId
            },
            emailSent: true,
            message: 'Savings Account Application Submitted Successfully!'
          });
        })
        .catch(emailErr => {
          console.error('❌ Email failed (Savings):', emailErr);
          res.render('process-confirmation', {
            application: {
              full_name: user.full_name,
              email: user.email,
              phone_number: user.phone_number,
              card_type: 'Savings Account',
              status: 'pending',
              application_id: result.insertId
            },
            emailSent: false,
            message: 'Savings Account Application Submitted! However, we were unable to send the confirmation email.'
          });
        });
    });
  });
});

function sendConfirmationEmailStatus(to, name, accountType, status) {
  const subject = `Your ${accountType} Account Application Status`;
  const html = `
  <p>Dear ${name},</p>
  <p>We’ve received your <strong>${accountType}</strong> application. Its current status is: <strong>${status}</strong>.</p>
  <p>You will receive another update once it has been reviewed. Thank you for choosing HOH Bank.</p>
  `;  
 
  return transporter.sendMail({
    from: '"HOH Bank" <TheOfficalHOH@gmail.com>',
    to,
    subject,
    html
  });
}

app.post('/submit-fixed-account', upload.single('photo'), (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');

  const user = req.session.user;

  // Step 1: Check for existing pending/approved fixed deposit application
  const checkSql = `
    SELECT * FROM account_applications
    WHERE user_id = ? AND account_type = 'fixed_deposit' AND status IN ('pending', 'approved')
  `;

  db.query(checkSql, [user.user_id], (checkErr, existingApps) => {
    if (checkErr) {
      console.error('❌ DB error during fixed deposit app check:', checkErr);
      return res.status(500).send('Database error while checking existing applications.');
    }

    if (existingApps.length > 0) {
      return res.send(`
        <script>
          alert("A pending application is currently under review for this product. Please wait for an email update from HOH Bank before applying again.");
          window.location.href = "/my-products";
        </script>
      `);
    }

    // Step 2: No existing app, proceed with new application submission
    const {
      nationality = '',
      income_source = 0.00,
      address = ''
    } = req.body;

    const student_id_upload_path = req.file ? req.file.path : '';
    const dob = new Date(user.date_of_birth).toISOString().split('T')[0];
    const productId = 4; // fixed deposit product ID

    const insertQuery = `
      INSERT INTO account_applications (
        user_id, product_id, full_name, email, phone_number, date_of_birth, nric,
        nationality, income_source, address, student_id_upload_path,
        account_type, status, kyc_verified, submitted_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'fixed_deposit', 'pending', false, NOW())
    `;

    const values = [
      user.user_id, productId, user.full_name, user.email, user.phone_number, dob, user.nric,
      nationality, income_source, address, student_id_upload_path
    ];

    db.query(insertQuery, values, (err, result) => {
      if (err) {
        console.error('❌ Insert error (Fixed):', err);
        return res.status(500).send('Failed to submit application.');
      }

      sendConfirmationEmailStatus(user.email, user.full_name, 'Fixed Deposit Account', 'Pending')
        .then(() => {
          res.render('process-confirmation', {
            application: {
              full_name: user.full_name,
              email: user.email,
              phone_number: user.phone_number,
              card_type: 'Fixed Deposit Account',
              status: 'pending',
              application_id: result.insertId
            },
            emailSent: true,
            message: 'Fixed Deposit Account Application Submitted Successfully!'
          });
        })
        .catch(emailErr => {
          console.error('❌ Email failed (Fixed):', emailErr);
          res.render('process-confirmation', {
            application: {
              full_name: user.full_name,
              email: user.email,
              phone_number: user.phone_number,
              card_type: 'Fixed Deposit Account',
              status: 'pending',
              application_id: result.insertId
            },
            emailSent: false,
            message: 'Fixed Deposit Application Submitted! However, we were unable to send the confirmation email.'
          });
        });
    });
  });
});


//Staff Card Management Routes
// Unified staff card action route for the new card management interface
app.post('/staff/card/action', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const { application_id, action, rejection_reason } = req.body;

  if (!['accept', 'reject'].includes(action)) {
    return res.redirect('/staff/card-management');
  }

  const getAppQuery = `SELECT * FROM card_applications WHERE application_id = ?`;
  db.query(getAppQuery, [application_id], (err, results) => {
    if (err || results.length === 0) {
      console.error(err || 'No application found');
      return res.status(500).send("Application not found or DB error");
    }

    const app = results[0];
    const newStatus = action === 'accept' ? 'approved' : 'rejected';
    const kyc = 1;

    // Update the card application status
    const updateQuery = `UPDATE card_applications SET status = ?, kyc_verified = ?, rejection_reason = ? WHERE application_id = ?`;
    db.query(updateQuery, [newStatus, kyc, rejection_reason || null, application_id], (updateErr) => {
      if (updateErr) {
        console.error(updateErr);
        return res.status(500).send("Failed to update status");
      }

      if (action === 'accept') {
        const cvv = generateCVV();
        const expiryDate = new Date();
        expiryDate.setFullYear(expiryDate.getFullYear() + 4);
        const formattedExpiry = expiryDate.toISOString().split('T')[0];
        const cardNumber = generateRandomNumber(9);
        const accountNumber = generateRandomNumber(9);
        const accountType = app.card_type === 'credit' ? 'credit_account' : 'debit_account';

        // Set initial balance: 2000 if credit, 0 if debit
        const initialBalance = app.card_type === 'credit' ? 2000.00 : 0.00;

        // Step 1: Create account
        const insertAccountQuery = `
          INSERT INTO accounts (user_id, product_id, full_name, account_number, account_type, balance, account_status)
          VALUES (?, ?, ?, ?, ?, ?, 'active')
        `;
        db.query(insertAccountQuery, [
          app.user_id,
          app.product_id,
          app.full_name,
          accountNumber,
          accountType,
          initialBalance
        ], (accErr, accResult) => {
          if (accErr) {
            console.error('Insert account error:', accErr);
            return res.status(500).send("Failed to create account");
          }

          const accountId = accResult.insertId;

          // Step 2: Create card with same balance
          const insertCardQuery = `
            INSERT INTO cards 
            (user_id, product_id, account_id, full_name, card_number, card_type, expiry_date, cvv, balance, card_status, issued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NOW())
          `;
          db.query(insertCardQuery, [
            app.user_id,
            app.product_id,
            accountId,
            app.full_name,
            cardNumber,
            app.card_type,
            formattedExpiry,
            cvv,
            initialBalance
          ], (cardErr) => {
            if (cardErr) {
              console.error('Insert card error:', cardErr);
              return res.status(500).send("Failed to issue card");
            }

            sendApprovalEmail(app.email, app.full_name)
              .then(() => res.redirect('/staff/card-management'))
              .catch(emailErr => {
                console.error('Email failed:', emailErr);
                res.redirect('/staff/card-management');
              });
          });
        });
      } else {
        const reasonText = rejection_reason || "No reason provided";
        sendRejectionEmail(app.email, app.full_name, reasonText)
          .then(() => res.redirect('/staff/card-management'))
          .catch(emailErr => {
            console.error('Rejection email failed:', emailErr);
            res.redirect('/staff/card-management');
          });
      }
    });
  });
});

// Staff card management route - unified interface for card applications
app.get('/staff/card-management', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const pendingQuery = `SELECT * FROM card_applications WHERE status = 'pending' ORDER BY submitted_at DESC`;
  const approvedQuery = `SELECT * FROM card_applications WHERE status = 'approved' ORDER BY submitted_at DESC`;
  const rejectedQuery = `SELECT * FROM card_applications WHERE status = 'rejected' ORDER BY submitted_at DESC`;

  db.query(pendingQuery, (err1, pending) => {
    if (err1) return res.status(500).send("Failed to load pending cards");

    db.query(approvedQuery, (err2, approved) => {
      if (err2) return res.status(500).send("Failed to load approved cards");

      db.query(rejectedQuery, (err3, rejected) => {
        if (err3) return res.status(500).send("Failed to load rejected cards");

        res.render('staff-card-management', {
          pendingCards: pending,
          approvedCards: approved,
          rejectedCards: rejected
        });
      });
    });
  });
});

// Route to view all current accounts
app.get('/staff/all-accounts', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const searchQuery = req.query.search || '';
  const statusFilter = req.query.status || '';
  
  let query = `
    SELECT 
      a.account_id,
      a.user_id,
      a.full_name,
      a.account_number,
      a.account_type,
      a.balance,
      a.account_status,
      a.created_at,
      p.product_name
    FROM accounts a
    LEFT JOIN product_catalog p ON a.product_id = p.product_id
  `;
  
  let params = [];
  let whereConditions = [];

  if (searchQuery) {
    whereConditions.push(`(a.full_name LIKE ? OR a.account_number LIKE ? OR a.account_type LIKE ?)`);
    const likeQuery = `%${searchQuery}%`;
    params.push(likeQuery, likeQuery, likeQuery);
  }

  if (statusFilter) {
    whereConditions.push(`a.account_status = ?`);
    params.push(statusFilter);
  }

  if (whereConditions.length > 0) {
    query += ` WHERE ${whereConditions.join(' AND ')}`;
  }

  query += ` ORDER BY a.created_at DESC`;

  try {
    const [accounts] = await db.promise().query(query, params);
    res.render('accounts', { 
      accounts, 
      searchQuery, 
      statusFilter 
    });
  } catch (err) {
    console.error('Error fetching accounts:', err);
    res.status(500).send('Error retrieving accounts');
  }
});

// CSV Export route for all accounts
app.get('/export/all-accounts', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  try {
    const [accounts] = await db.promise().query(`
      SELECT 
        a.account_id,
        a.user_id,
        a.full_name,
        a.account_number,
        a.account_type,
        a.balance,
        a.account_status,
        a.created_at,
        p.product_name,
        u.email,
        u.phone_number,
        u.nric
      FROM accounts a
      LEFT JOIN product_catalog p ON a.product_id = p.product_id
      LEFT JOIN users u ON a.user_id = u.user_id
      ORDER BY a.created_at DESC
    `);

    if (accounts.length === 0) {
      return res.status(404).send('No accounts found to export');
    }

    // Define CSV fields
    const fields = [
      { label: 'Account ID', value: 'account_id' },
      { label: 'User ID', value: 'user_id' },
      { label: 'Full Name', value: 'full_name' },
      { label: 'Email', value: 'email' },
      { label: 'Phone Number', value: 'phone_number' },
      { label: 'NRIC', value: 'nric' },
      { label: 'Account Number', value: 'account_number' },
      { label: 'Account Type', value: 'account_type' },
      { label: 'Balance', value: 'balance' },
      { label: 'Account Status', value: 'account_status' },
      { label: 'Product Name', value: 'product_name' },
      { label: 'Created At', value: 'created_at' }
    ];

    // Format data for CSV
    const formattedAccounts = accounts.map(account => ({
      ...account,
      account_type: account.account_type.replace('_', ' ').toUpperCase(),
      account_status: account.account_status.toUpperCase(),
      balance: parseFloat(account.balance || 0).toFixed(2),
      created_at: account.created_at ? new Date(account.created_at).toLocaleString() : 'N/A',
      email: account.email || 'N/A',
      phone_number: account.phone_number || 'N/A',
      nric: account.nric || 'N/A',
      product_name: account.product_name || 'N/A'
    }));

    const parser = new Parser({ fields });
    const csv = parser.parse(formattedAccounts);

    // Set headers for file download
    const filename = `all_accounts_export_${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.send(csv);
  } catch (err) {
    console.error('Error exporting accounts:', err);
    res.status(500).send('Failed to export accounts data');
  }
});

// CSV Export route for cards
app.get('/export/cards', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  try {
    const [cards] = await db.promise().query(`
      SELECT 
        c.card_id,
        c.user_id,
        u.full_name,
        u.email,
        u.phone_number,
        u.nric,
        c.card_number,
        c.card_type,
        c.cvv,
        c.balance,
        c.expiry_date,
        c.card_status,
        c.issued_at
      FROM cards c
      JOIN users u ON c.user_id = u.user_id
      ORDER BY c.issued_at DESC
    `);

    if (cards.length === 0) {
      return res.status(404).send('No cards found to export');
    }

    // Define CSV fields
    const fields = [
      { label: 'Card ID', value: 'card_id' },
      { label: 'User ID', value: 'user_id' },
      { label: 'Full Name', value: 'full_name' },
      { label: 'Email', value: 'email' },
      { label: 'Phone Number', value: 'phone_number' },
      { label: 'NRIC', value: 'nric' },
      { label: 'Card Number', value: 'card_number' },
      { label: 'Card Type', value: 'card_type' },
      { label: 'CVV', value: 'cvv' },
      { label: 'Balance', value: 'balance' },
      { label: 'Expiry Date', value: 'expiry_date' },
      { label: 'Card Status', value: 'card_status' },
      { label: 'Issued At', value: 'issued_at' }
    ];

    // Format data for CSV
    const formattedCards = cards.map(card => ({
      ...card,
      balance: parseFloat(card.balance || 0).toFixed(2),
      expiry_date: card.expiry_date ? new Date(card.expiry_date).toLocaleDateString() : 'N/A',
      issued_at: card.issued_at ? new Date(card.issued_at).toLocaleString() : 'N/A',
      email: card.email || 'N/A'
    }));

    const parser = new Parser({ fields });
    const csv = parser.parse(formattedCards);

    // Set headers for file download
    const filename = `cards_export_${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.send(csv);
  } catch (err) {
    console.error('Error exporting cards:', err);
    res.status(500).send('Failed to export cards data');
  }
});

// CSV Export route for users (bonus - since you have user management)
app.get('/export/all-users', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  try {
    const [users] = await db.promise().query(`
      SELECT 
        user_id,
        full_name,
        email,
        phone_number,
        role,
        date_of_birth,
        nric,
        created_at
      FROM users
      ORDER BY created_at DESC
    `);

    if (users.length === 0) {
      return res.status(404).send('No users found to export');
    }

    // Define CSV fields
    const fields = [
      { label: 'User ID', value: 'user_id' },
      { label: 'Full Name', value: 'full_name' },
      { label: 'Email', value: 'email' },
      { label: 'Phone Number', value: 'phone_number' },
      { label: 'Role', value: 'role' },
      { label: 'Date of Birth', value: 'date_of_birth' },
      { label: 'NRIC', value: 'nric' },
      { label: 'Created At', value: 'created_at' }
    ];

    // Format data for CSV
    const formattedUsers = users.map(user => ({
      ...user,
      date_of_birth: user.date_of_birth ? new Date(user.date_of_birth).toLocaleDateString() : 'N/A',
      created_at: user.created_at ? new Date(user.created_at).toLocaleString() : 'N/A'
    }));

    const parser = new Parser({ fields });
    const csv = parser.parse(formattedUsers);

    // Set headers for file download
    const filename = `users_export_${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.send(csv);
  } catch (err) {
    console.error('Error exporting users:', err);
    res.status(500).send('Failed to export users data');
  }
});



// CSV Export route for transactions
app.get('/export/transactions', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  try {
    const userId = req.query.user_id || null;
    let query = `
      SELECT 
        u.full_name,
        a.account_number,
        a.account_type,
        t.transaction_type,
        t.amount,
        t.description,
        t.transaction_date
      FROM transactions t
      JOIN accounts a ON t.account_id = a.account_id
      JOIN users u ON a.user_id = u.user_id
    `;
    let params = [];

    if (userId) {
      query += ' WHERE u.user_id = ?';
      params = [userId];
    }

    query += ' ORDER BY t.transaction_date DESC';

    const [transactions] = await db.promise().query(query, params);

    if (transactions.length === 0) {
      return res.status(404).send('No transactions found to export');
    }

    // Define CSV fields
    const fields = [
      { label: 'Full Name', value: 'full_name' },
      { label: 'Account Number', value: 'account_number' },
      { label: 'Account Type', value: 'account_type' },
      { label: 'Transaction Type', value: 'transaction_type' },
      { label: 'Amount', value: 'amount' },
      { label: 'Description', value: 'description' },
      { label: 'Transaction Date', value: 'transaction_date' }
    ];

    // Format data for CSV
    const formattedTransactions = transactions.map(tx => ({
      ...tx,
      account_type: tx.account_type.replace('_', ' ').toUpperCase(),
      transaction_type: tx.transaction_type.charAt(0).toUpperCase() + tx.transaction_type.slice(1),
      amount: parseFloat(tx.amount || 0).toFixed(2),
      transaction_date: tx.transaction_date ? new Date(tx.transaction_date).toLocaleString() : 'N/A'
    }));

    const parser = new Parser({ fields });
    const csv = parser.parse(formattedTransactions);

    // Set headers for file download
    const userFilter = userId ? `_user_${userId}` : '_all_users';
    const filename = `transactions_export${userFilter}_${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.send(csv);
  } catch (err) {
    console.error('Error exporting transactions:', err);
    res.status(500).send('Failed to export transactions data');
  }
});

// CSV Export route for products
app.get('/export/products', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  try {
    const [products] = await db.promise().query(`
      SELECT 
        product_id,
        product_name,
        product_type,
        description
      FROM product_catalog
      ORDER BY product_id ASC
    `);

    if (products.length === 0) {
      return res.status(404).send('No products found to export');
    }

    // Define CSV fields
    const fields = [
      { label: 'Product ID', value: 'product_id' },
      { label: 'Product Name', value: 'product_name' },
      { label: 'Product Type', value: 'product_type' },
      { label: 'Description', value: 'description' }
    ];

    // Format data for CSV
    const formattedProducts = products.map(product => ({
      ...product,
      product_type: product.product_type.replace('_', ' ').toUpperCase()
    }));

    const parser = new Parser({ fields });
    const csv = parser.parse(formattedProducts);

    // Set headers for file download
    const filename = `product_catalog_export_${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.send(csv);
  } catch (err) {
    console.error('Error exporting products:', err);
    res.status(500).send('Failed to export products data');
  }
});
// POST: Open fixed deposit account
app.post('/open-fixed', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login/customer');
  }

  const user = req.session.user;
  const checkSql = `SELECT * FROM accounts WHERE user_id = ? AND account_type = 'fixed_deposit' AND account_status = 'active'`;

  db.query(checkSql, [user.user_id], (err, rows) => {
    if (err) {
      console.error('Check fixed deposit error:', err);
      return res.status(500).send('Server error');
    }
    if (rows.length > 0) {
      return res.send(`<script>alert('You already have a fixed deposit account.'); window.location.href='/my-products';</script>`);
    }

    const productId = 4;
    const accountNumber = generateRandomNumber(9);
    const insertSql = `
      INSERT INTO accounts (user_id, product_id, full_name, account_number, account_type, balance, account_status)
      VALUES (?, ?, ?, ?, 'fixed_deposit', 0.00, 'active')
    `;
    db.query(insertSql, [user.user_id, productId, user.full_name, accountNumber], (err2) => {
      if (err2) {
        console.error('Insert fixed deposit error:', err2);
        return res.status(500).send('Failed to create fixed deposit account');
      }
      res.redirect('/dashboard');
    });
  });
});
// POST: Instantly open savings account
app.post('/open-savings', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login/customer');
  }

  const user = req.session.user;
  const checkSql = `SELECT * FROM accounts WHERE user_id = ? AND account_type = 'savings' AND account_status = 'active'`;

  db.query(checkSql, [user.user_id], (err, rows) => {
    if (err) {
      console.error('Check savings account error:', err);
      return res.status(500).send('Server error');
    }
    if (rows.length > 0) {
      return res.send(`<script>alert('You already have a savings account.'); window.location.href='/my-products';</script>`);
    }

    // Proceed to insert since no active savings account exists
    const productId = 3;
    const accountNumber = generateRandomNumber(9);
    const insertSql = `
      INSERT INTO accounts (user_id, product_id, full_name, account_number, account_type, balance, account_status)
      VALUES (?, ?, ?, ?, 'savings', 0.00, 'active')
    `;
    db.query(insertSql, [user.user_id, productId, user.full_name, accountNumber], (err2) => {
      if (err2) {
        console.error('Insert savings account error:', err2);
        return res.status(500).send('Failed to create savings account');
      }
      res.redirect('/dashboard');
    });
  });
});


//jeli-----------------------------------------------------------------
// Credit Education and Resources Routes
//Financial Education Page
app.get('/financial-education', (req, res) => {
  res.render('financial-education');
});

//Financial Resources for Students
app.get('/financial-resources', (req, res) => {
  res.render('financial-resources');
});

// Financial Education Quiz
app.get('/financial-quiz', (req, res) => {
  res.render('financial-quiz');
});

// Function to calculate quiz score
function calculateQuizScore(answers) {
  const correct = {
    q1: 'B',  // Safe place to store money and earn interest
    q2: 'B',  // Tracking expenses regularly
    q3: 'B',  // Save a portion of income before spending
    q4: 'B',  // Money locked in and earns higher interest
    q5: 'A',  // Using an account with compound interest
    q6: 'C',  // Catch errors and monitor spending habits
    q7: 'C',  // Want higher guaranteed interest
    q8: 'A',  // Stick to a written or digital budget
    q9: 'C',  // You earn interest on your savings and its interest
    q10: 'A'  // Save $500 in 3 months
  };

  let score = 0;
  Object.keys(correct).forEach((key) => {
    if (answers[key] && answers[key] === correct[key]) {
      score++;
    }
  });

  return score;
}

// POST: Submit Financial Quiz (using callbacks instead of async/await)
app.post('/submit-quiz', (req, res) => {
  const answers = req.body;
  const score = calculateQuizScore(answers);

  // Check if user is logged in
  if (!req.session.user || !req.session.user.user_id) {
    return res.redirect('/login/customer');
  }

  // ✅ SAVE QUIZ SCORE TO DATABASE FIRST
  const insertScoreSql = `INSERT INTO credit_quiz_scores (user_id, score) VALUES (?, ?)`;
  db.query(insertScoreSql, [req.session.user.user_id, score], (scoreErr) => {
    if (scoreErr) {
      console.error('Error saving quiz score:', scoreErr);
      // Continue with rest of logic even if score saving fails
    }

    // Optional: basic rate limit using session to limit reward claims
    if (!req.session.rewardClaimed) {
      if (score === 10) {
        // Use callback-based query
        db.query(`SELECT COUNT(*) AS total FROM reward_claims`, (err, claimedCount) => {
          if (err) {
            console.error('Database error:', err);
            return res.render('quiz-result', { 
              score, 
              reward: false, 
              exhausted: false,
              error: 'There was an error submitting your quiz. Please try again.' 
            });
          }

          if (claimedCount[0].total < 50) {
            db.query(`INSERT INTO reward_claims (user_id, reward_type) VALUES (?, ?)`, [
              req.session.user.user_id,
              'Artease/Kofu $2'
            ], (insertErr) => {
              if (insertErr) {
                console.error('Insert error:', insertErr);
                return res.render('quiz-result', { 
                  score, 
                  reward: false, 
                  exhausted: false,
                  error: 'There was an error claiming your reward. Please try again.' 
                });
              }
              
              req.session.rewardClaimed = true;
              return res.render('quiz-result', { score, reward: true, exhausted: false });
            });
          } else {
            // All vouchers claimed
            return res.render('quiz-result', { score, reward: false, exhausted: true });
          }
        });
      } else {
        // Score is not 10, no reward
        res.render('quiz-result', { score, reward: false, exhausted: false });
      }
    } else {
      // Reward already claimed
      res.render('quiz-result', { score, reward: false, exhausted: false });
    }
  });
});

//For staff monitor financial education quiz results
app.get('/staff/quiz-monitor', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  try {
    const [results] = await db.promise().query(`
      SELECT q.quiz_id, u.full_name, u.email, q.score, q.taken_on
      FROM credit_quiz_scores q
      JOIN users u ON q.user_id = u.user_id
      ORDER BY q.taken_on DESC
    `);

    res.render('staff-quiz-monitor', { results });
  } catch (error) {
    console.error('Quiz monitor error:', error);
    res.render('staff-quiz-monitor', { results: [], error: 'Failed to load data' });
  }
});

//Export quiz results to CSV
// Staff Quiz Monitor Export Route (using callbacks instead of async/await)
app.get('/exports/staff-quizmonitor', (req, res) => {
  // Check if user is staff/admin
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.status(403).json({ error: 'Access denied. Staff access required.' });
  }

  // Updated query - removed first_name and last_name since they don't exist
  const query = `
    SELECT 
      u.user_id,
      u.full_name,
      u.email,
      cqs.score,
      cqs.taken_on as date_taken
    FROM credit_quiz_scores cqs
    JOIN users u ON cqs.user_id = u.user_id
    ORDER BY cqs.taken_on DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Export error:', err);
      return res.status(500).json({ error: 'Failed to export quiz data' });
    }

    // Generate CSV content manually (no external library needed)
    let csvContent = "No,Full Name,Email,Score,Date Taken\n";
    
    results.forEach((row, index) => {
      // Use only full_name since first_name/last_name don't exist
      const fullName = row.full_name || 'N/A';
      const dateTaken = new Date(row.date_taken).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
      
      // Escape CSV fields properly (wrap in quotes and escape internal quotes)
      const escapedFullName = `"${(fullName || '').replace(/"/g, '""')}"`;
      const escapedEmail = `"${(row.email || '').replace(/"/g, '""')}"`;
      const score = `"${row.score}/10"`;
      const escapedDate = `"${dateTaken}"`;
      
      csvContent += `${index + 1},${escapedFullName},${escapedEmail},${score},${escapedDate}\n`;
    });

    // Generate filename with current date
    const now = new Date();
    const filename = `student_quiz_results_${now.getFullYear()}-${(now.getMonth()+1).toString().padStart(2,'0')}-${now.getDate().toString().padStart(2,'0')}.csv`;

    // Set proper headers for CSV download
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Pragma', 'no-cache');

    // Send CSV content as text (not JSON)
    res.send(csvContent);
  });
});



// Profile Page Routes
// Profile Page
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  res.render('user-profile', { user: req.session.user });
});

// Staff Profile Routes
// GET: Staff Profile View Page (Read-only)
app.get('/staff/profile', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const userId = req.session.user.user_id;
  
  const query = 'SELECT * FROM users WHERE user_id = ? AND role = "staff"';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching staff profile:', err);
      return res.status(500).send('Database error');
    }

    if (results.length === 0) {
      return res.status(404).send('Staff profile not found');
    }

    const staff = results[0];
    res.render('staff-profile', { 
      staff, 
      message: req.query.message || null,
      error: req.query.error || null 
    });
  });
});

// GET: Staff Profile Edit Page
app.get('/staff/profile/edit', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const userId = req.session.user.user_id;
  
  const query = 'SELECT * FROM users WHERE user_id = ? AND role = "staff"';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching staff profile:', err);
      return res.status(500).send('Database error');
    }

    if (results.length === 0) {
      return res.status(404).send('Staff profile not found');
    }

    const staff = results[0];
    res.render('staff-update-profile', { 
      staff, 
      message: req.query.message || null,
      error: req.query.error || null 
    });
  });
});

// POST: Update Staff Profile
app.post('/staff/profile/update', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const userId = req.session.user.user_id;
  const { full_name, email, phone_number, date_of_birth } = req.body;

  // Validate required fields
  if (!full_name || !email || !phone_number) {
    return res.redirect('/staff/profile/edit?error=Please fill in all required fields');
  }

  const updateQuery = `
    UPDATE users 
    SET full_name = ?, email = ?, phone_number = ?, date_of_birth = ?
    WHERE user_id = ? AND role = 'staff'
  `;

  db.query(updateQuery, [full_name, email, phone_number, date_of_birth, userId], (err, result) => {
    if (err) {
      console.error('Error updating staff profile:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.redirect('/staff/profile/edit?error=Email already exists');
      }
      return res.redirect('/staff/profile/edit?error=Failed to update profile');
    }

    if (result.affectedRows === 0) {
      return res.redirect('/staff/profile/edit?error=Profile not found');
    }

    // Update session data
    req.session.user.full_name = full_name;
    req.session.user.email = email;
    req.session.user.phone_number = phone_number;

    // Send notification email
    sendStaffProfileUpdateNotification(full_name, email, userId)
      .then(() => {
        res.redirect('/staff/profile?message=Profile updated successfully');
      })
      .catch(emailErr => {
        console.error('Email notification failed:', emailErr);
        res.redirect('/staff/profile?message=Profile updated successfully (email notification failed)');
      });
  });
});

// POST: Change Staff Password (Step 1: Generate OTP)
app.post('/staff/profile/change-password', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const userId = req.session.user.user_id;
  const { current_password, new_password, confirm_password } = req.body;

  // Basic validations
  if (!current_password || !new_password || !confirm_password) {
    return res.redirect('/staff/profile/edit?error=Please fill in all password fields');
  }

  if (new_password !== confirm_password) {
    return res.redirect('/staff/profile/edit?error=New passwords do not match');
  }

  if (new_password.length < 6) {
    return res.redirect('/staff/profile/edit?error=New password must be at least 6 characters');
  }

  const getUserQuery = 'SELECT * FROM users WHERE user_id = ? AND role = "staff"';
  db.query(getUserQuery, [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.redirect('/staff/profile/edit?error=User not found');
    }

    const staff = results[0];

    // Check current password
    if (staff.password !== current_password) {
      return res.redirect('/staff/profile/edit?error=Current password is incorrect');
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store OTP and new password in session (expires in 10 minutes)
    req.session.staffOtp = otp;
    req.session.pendingPassword = new_password;
    req.session.otpTimestamp = Date.now();

    // Send OTP via email
    const subject = 'HOH Bank - Password Change Verification';
    const html = `
      <h3>Password Change Verification</h3>
      <p><strong>Staff Member:</strong> ${staff.full_name}</p>
      <p><strong>Action:</strong> Password change request</p>
      <p><strong>Verification Code:</strong> <span style="font-size: 24px; font-weight: bold; color: #22c55e;">${otp}</span></p>
      <p><strong>Valid for:</strong> 10 minutes</p>
      <br/>
      <p>If you did not request this password change, please contact your administrator immediately.</p>
      <p>This is an automated message from HOH Bank Staff Management System.</p>
    `;

    sendEmail(staff.email, subject, html)
      .then(() => {
        res.redirect('/staff/profile/verify-otp');
      })
      .catch(emailErr => {
        console.error('Email notification failed:', emailErr);
        res.redirect('/staff/profile/edit?error=Failed to send verification email. Please try again.');
      });
  });
});

// GET: Staff Password OTP Verification Page
app.get('/staff/profile/verify-otp', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  // Check if OTP exists in session
  if (!req.session.staffOtp || !req.session.pendingPassword) {
    return res.redirect('/staff/profile/edit?error=No OTP verification in progress');
  }

  // Check if OTP has expired (10 minutes)
  const otpAge = Date.now() - req.session.otpTimestamp;
  if (otpAge > 10 * 60 * 1000) { // 10 minutes in milliseconds
    delete req.session.staffOtp;
    delete req.session.pendingPassword;
    delete req.session.otpTimestamp;
    return res.redirect('/staff/profile/edit?error=OTP has expired. Please try again.');
  }

  res.render('staff-password-otp', {
    error: req.query.error || null,
    message: req.query.message || null,
    user: req.session.user
  });
});

// POST: Verify OTP and Update Password
app.post('/staff/profile/verify-otp', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const { otp } = req.body;
  const userId = req.session.user.user_id;

  // Check if OTP exists in session
  if (!req.session.staffOtp || !req.session.pendingPassword) {
    return res.redirect('/staff/profile/edit?error=No OTP verification in progress');
  }

  // Check if OTP has expired (10 minutes)
  const otpAge = Date.now() - req.session.otpTimestamp;
  if (otpAge > 10 * 60 * 1000) { // 10 minutes in milliseconds
    delete req.session.staffOtp;
    delete req.session.pendingPassword;
    delete req.session.otpTimestamp;
    return res.redirect('/staff/profile/edit?error=OTP has expired. Please try again.');
  }

  // Validate OTP
  if (!otp || otp.trim() === '') {
    return res.redirect('/staff/profile/verify-otp?error=Please enter the OTP');
  }

  if (otp !== req.session.staffOtp) {
    return res.redirect('/staff/profile/verify-otp?error=Invalid OTP. Please check your email and try again.');
  }

  // OTP is valid - update password
  const newPassword = req.session.pendingPassword;
  const updateQuery = 'UPDATE users SET password = ? WHERE user_id = ? AND role = "staff"';
  
  db.query(updateQuery, [newPassword, userId], (updateErr, result) => {
    if (updateErr) {
      console.error('Error updating password:', updateErr);
      return res.redirect('/staff/profile/verify-otp?error=Failed to update password');
    }

    // Get staff info for notification
    const getUserQuery = 'SELECT * FROM users WHERE user_id = ? AND role = "staff"';
    db.query(getUserQuery, [userId], (err, results) => {
      if (err || results.length === 0) {
        console.error('Error getting user info for notification:', err);
      } else {
        const staff = results[0];
        
        // Send password change confirmation email
        sendPasswordChangeNotification(staff.full_name, staff.email, userId)
          .catch(emailErr => {
            console.error('Password change notification failed:', emailErr);
          });
      }
    });

    // Clear OTP session data
    delete req.session.staffOtp;
    delete req.session.pendingPassword;
    delete req.session.otpTimestamp;

    // Redirect with success message
    res.redirect('/staff/profile?message=Password changed successfully');
  });
});

// Staff Profile Email notification functions
function sendPasswordChangeNotification(fullName, toEmail, userId) {
  const mailOptions = {
    from: 'TheOfficalHOH@gmail.com',
    to: toEmail,
    subject: 'HOH Bank – Staff Password Change Alert',
    html: `
      <p>Dear ${fullName},</p>
      <p>Your password for HOH Bank Staff account (User ID: ${userId}) has been changed successfully.</p>
      <p>If this was not you, please contact IT support immediately.</p>
      <br/>
      <p>Regards,<br/>HOH Security Team</p>
    `
  };

  return transporter.sendMail(mailOptions);
}

// MyInfo Callback
app.get('/myinfo/auth', (req, res) => {
  res.redirect('/myinfo/callback');
});


const fetch = require('node-fetch');

app.get('/myinfo/callback', async (req, res) => {
  try {
    const sampleUinfin = 'S9812381D';
    const response = await fetch(`https://sandbox.api.myinfo.gov.sg/com/v4/person-sample/${sampleUinfin}`);
    const user = await response.json();

    const full_name = user.name?.value || '';
    const nric = user.uinfin?.value || '';
    const date_of_birth = user.dob?.value || '';
    const address = `${user.regadd?.block?.value || ''} ${user.regadd?.street?.value || ''} #${user.regadd?.floor?.value || ''}-${user.regadd?.unit?.value || ''} S${user.regadd?.postal?.value || ''}`;
    const email = user.email?.value || '';

    // Fix phone extraction for MyInfo sample
    let phone = '';
    if (user.mobileno) {
      if (typeof user.mobileno.nbr === 'string') {
        phone = user.mobileno.nbr;
      } else if (user.mobileno.nbr && typeof user.mobileno.nbr.value === 'string') {
        phone = user.mobileno.nbr.value;
      } else {
        phone = '';
      }
    }

    res.render('customer-signup', {
      myinfo: {
        full_name,
        nric,
        date_of_birth,
        address,
        email,
        phone: phone
      }
    });
  } catch (error) {
    console.error("MyInfo error:", error.message);
    res.redirect('/signup/customer');
  }
});

// Reset Password
app.get('/reset-password', (req, res) => res.render('reset-password'));
app.post('/reset-password', authController.requestPasswordReset);
app.get('/verify-otp', (req, res) => res.render('verify-otp', { email: req.query.email }));
app.post('/verify-otp', authController.verifyOtp);
app.post('/set-new-password', authController.setNewPassword);

app.get('/dashboard/staff', async (req, res) => {
  const staffId = req.session.user?.user_id;
  if (!staffId) return res.redirect('/login/staff');

  try {
    const [rows] = await db.promise().query('SELECT * FROM users WHERE user_id = ?', [staffId]);
    if (rows.length === 0) return res.status(404).send('Staff not found.');
    const staff = rows[0];

    const [statusCountsResult] = await db.promise().query(`
      SELECT status, COUNT(*) AS count
      FROM account_applications
      GROUP BY status
    `);

    const statusCounts = {
      pending: 0,
      approved: 0,
      rejected: 0,
    };
    statusCountsResult.forEach(row => {
      if (row.status in statusCounts) {
        statusCounts[row.status] = row.count;
      }
    });

    const stats = { statusCounts };
    const [accountTypesResult] = await db.promise().query(`
      SELECT account_type, COUNT(*) AS count
      FROM accounts
      GROUP BY account_type
    `);

    const accountTypes = {
      savings: 0,
      fixedDeposit: 0,
      creditCard: 0,
      debitCard: 0
    };

    accountTypesResult.forEach(row => {
      const type = row.account_type;
      if (type === 'savings') accountTypes.savings = row.count;
      if (type === 'fixed_deposit') accountTypes.fixedDeposit = row.count;
      if (type === 'credit_account') accountTypes.creditCard = row.count;
      if (type === 'debit_account') accountTypes.debitCard = row.count;
    });

    stats.accountTypes = accountTypes; // ✅ Attach to stats

    // Get total accounts count
    const [totalAccountsResult] = await db.promise().query(`
      SELECT COUNT(*) as total FROM accounts
    `);
    stats.totalAccounts = totalAccountsResult[0].total;

    // In your staff dashboard route (around line 100-200), add this query
    const [monthlyTransactions] = await db.promise().query(`
      SELECT 
        MONTH(transaction_date) as month,
        COUNT(*) as transaction_count
      FROM transactions 
      WHERE YEAR(transaction_date) = YEAR(CURDATE())
      GROUP BY MONTH(transaction_date)
      ORDER BY MONTH(transaction_date)
    `);

    // Process the data to fill in missing months with 0
    const monthlyData = new Array(12).fill(0);
    monthlyTransactions.forEach(row => {
      monthlyData[row.month - 1] = row.transaction_count;
    });

    // Add to your stats object
    stats.monthlyTransactions = monthlyData;

    // NEW CODE: Add card counts query for the dashboard
    const [[pendingCards]] = await db.promise().query(
      `SELECT COUNT(*) as count FROM card_applications WHERE status = 'pending'`
    );
    const [[approvedCards]] = await db.promise().query(
      `SELECT COUNT(*) as count FROM card_applications WHERE status = 'approved'`
    );
    const [[rejectedCards]] = await db.promise().query(
      `SELECT COUNT(*) as count FROM card_applications WHERE status = 'rejected'`
    );

    // Add card counts to stats
    stats.cardCounts = {
      pending: pendingCards.count,
      approved: approvedCards.count,
      rejected: rejectedCards.count
    };

    // Consultation details for the dashboard
    const [consultationDetails] = await db.promise().query(`
      SELECT 
        c.consultation_id,
        c.appointment_date,
        TIME_FORMAT(c.appointment_date, '%H:%i') AS appointment_time,
        a.full_name AS advisor_name,
        s.full_name AS customer_name,
        c.status,
        c.notes
      FROM consultations c
      LEFT JOIN users a ON c.advisor_id = a.user_id AND a.role = 'financial_advisor'
      LEFT JOIN users s ON c.customer_id = s.user_id AND s.role = 'customer'
      WHERE c.status = 'accepted'
      ORDER BY c.appointment_date DESC
    `);

    
    // ✅ Calendar events
    const [consultations] = await db.promise().query(`
      SELECT appointment_date
      FROM consultations
      WHERE status = 'accepted'
    `);

    const consultationEvents = consultations.map(c => ({
      title: 'Consultation',
      start: c.appointment_date
    }));

    res.render('staff-dashboard', {
      staff,
      stats,
      consultationEvents,
      consultationDetails // ✅ included here
    });

  } catch (err) {
    console.error('Error loading staff dashboard:', err);
    res.status(500).send('Failed to load dashboard.');
  }
});




//////////////////////////////////////////////////////////
//alicia///////////////////////////////////////////////////////////////////////////////

app.get('/pdpa-policy', (req, res) => {
  res.render('pdpa-policy');
});
app.get('/terms', (req, res) => res.render('terms'));
// GET: Show create user form
app.get('/create-user', (req, res) => {
  res.render('create-user');
});

// POST: Handle create user form (no password encryption)
app.post('/create-user', (req, res) => {
  const {
    full_name,
    email,
    password,
    phone_number,
    role,
    date_of_birth,
    nric
  } = req.body;

  const insertUserSql = `
    INSERT INTO users (full_name, email, password, phone_number, role, date_of_birth, nric)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(insertUserSql, [full_name, email, password, phone_number, role, date_of_birth, nric], (err) => {
    if (err) {
      console.error('❌ Failed to create user:', err);
      return res.status(500).send('Failed to create user.');
    }

    // ✅ Redirect to staff dashboard after successful creation
    res.redirect('/dashboard/staff');
  });
});

// customer card
app.get("/apply-card", (req, res) => {
  const user = req.session.user;

  if (!user) {
    return res.redirect("/login/customer");
  }

  const userId = user.user_id;

  const productSql = "SELECT * FROM product_catalog";
  const cardSql = `
    SELECT DISTINCT c.card_type
    FROM cards c
    JOIN accounts a ON c.account_id = a.account_id
    WHERE a.user_id = ? AND c.card_status = 'active'
  `;

  db.query(productSql, (err, productResults) => {
    if (err) {
      console.error("Error fetching products:", err);
      return res.status(500).send("Database error");
    }

    db.query(cardSql, [userId], (cardErr, cardResults) => {
      if (cardErr) {
        console.error("Error fetching active cards:", cardErr);
        return res.status(500).send("Database error");
      }

      const ownedTypes = cardResults.map(row => row.card_type);
      res.render("apply-card", {
        products: productResults,
        ownedTypes
      });
    });
  });
});

app.get('/apply-account', (req, res) => {
  db.query('SELECT * FROM product_catalog WHERE product_type IN (?, ?)', ['savings', 'fixed_deposit'], (err, results) => {
    if (err) {
      console.error('Error fetching products:', err);
      return res.status(500).send('Server Error');
    }
    res.render('apply-account', { products: results }); // choose-account.ejs
  });
});

app.get('/debit-card', (req, res) => {
  const user = req.session.user; // use the whole session user object

  if (!user) {
    return res.redirect('/login/customer'); // adjust this path if needed
  }

  const query = 'SELECT * FROM users WHERE user_id = ?';

  db.query(query, [user.user_id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Database error');
    }

    if (results.length === 0) {
      return res.status(404).send('User not found');
    }

    const userData = results[0];
    res.render('debit-card', { user: userData }); // pass user data to your EJS page
  });
});
app.get('/top-up', (req, res) => {
  const userId = req.session.user?.user_id;
  if (!userId) return res.redirect('/login/customer-login');
  const sql = 'SELECT * FROM accounts WHERE user_id = ? AND account_status = "active"';

  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('Database error fetching accounts:', err);
      return res.status(500).send('Internal server error');
    }

    // Pass accounts to the top-up view
    res.render('top-up', { accounts: results });
  });
});
app.post('/paypal-success', (req, res) => {
  const { account_id, amount } = req.body || {};

  if (!account_id || !amount) {
    console.error('❌ Missing account_id or amount:', req.body);
    return res.status(400).send('Missing account_id or amount.');
  }

  const parsedAmount = parseFloat(amount);
  if (isNaN(parsedAmount) || parsedAmount <= 0) {
    console.error('❌ Invalid amount:', amount);
    return res.status(400).send('Invalid amount.');
  }

  db.beginTransaction(err => {
    if (err) {
      console.error('❌ Failed to start DB transaction:', err);
      return res.status(500).send('Failed to start transaction.');
    }

    const getAccountSql = `
      SELECT a.account_id, a.account_type, u.user_id, u.email, u.full_name
      FROM accounts a
      JOIN users u ON a.user_id = u.user_id
      WHERE a.account_id = ?
    `;

    db.query(getAccountSql, [account_id], (accErr, accResults) => {
      if (accErr || accResults.length === 0) {
        console.error('❌ Account not found or query error:', accErr);
        return db.rollback(() => res.status(500).send('Account not found.'));
      }

      const account = accResults[0];

      const updateAccountSql = `UPDATE accounts SET balance = balance + ? WHERE account_id = ?`;
      db.query(updateAccountSql, [parsedAmount, account_id], (acctErr) => {
        if (acctErr) {
          console.error('❌ Failed to update account balance:', acctErr);
          return db.rollback(() => res.status(500).send('Failed to update account.'));
        }

        const updateCardIfNeeded = (next) => {
          if (['credit_account', 'debit_account'].includes(account.account_type)) {
            const updateCardSql = `
              UPDATE cards
              SET balance = COALESCE(balance, 0) + ?
              WHERE account_id = ? AND card_status = 'active'
            `;
            db.query(updateCardSql, [parsedAmount, account.account_id], (cardErr) => {
              if (cardErr) {
                console.error('❌ Failed to update card balance:', cardErr);
                return db.rollback(() => res.status(500).send('Card update failed.'));
              }
              next();
            });
          } else {
            next();
          }
        };

        const insertTransaction = () => {
          const insertTxSql = `
            INSERT INTO transactions (account_id, transaction_type, amount, description)
            VALUES (?, 'topup', ?, 'Top-up via PayPal')
          `;
          db.query(insertTxSql, [account.account_id, parsedAmount], (txErr) => {
            if (txErr) {
              console.error('❌ Failed to insert transaction:', txErr);
              return db.rollback(() => res.status(500).send('Transaction log failed.'));
            }

            db.commit(commitErr => {
              if (commitErr) {
                console.error('❌ Commit failed:', commitErr);
                return db.rollback(() => res.status(500).send('Failed to commit transaction.'));
              }

              // ✅ Email after successful top-up
              sendEmail(
                account.email,
                "Top-Up Successful",
                `Hello ${account.full_name}, your account has been topped up with $${parsedAmount.toFixed(2)} via PayPal.`
              );

              console.log(`✅ Top-up successful for account ${account.account_id}`);
              res.status(200).send('Top-up successful' + (['credit_account', 'debit_account'].includes(account.account_type) ? ' (account + card)' : ' (account only)'));
            });
          });
        };

        updateCardIfNeeded(insertTransaction);
      });
    });
  });
});
app.get('/pay-bank', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer-login');

  const userId = req.session.user.user_id;

  db.query("SELECT * FROM accounts WHERE user_id = ?", [userId], (err, accounts) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Failed to get accounts");
    }

    // Extract all account IDs for this user
    const accountIds = accounts.map(acc => acc.account_id);
    if (accountIds.length === 0) {
      // User has no accounts, so credit owed is full $2000
      return res.render("pay-bank", { accounts, creditRemaining: "2000.00" });
    }

    // Prepare SQL with account IDs in WHERE clause
    const repaymentQuery = `
      SELECT COALESCE(SUM(amount), 0) AS total_repaid
      FROM transactions
      WHERE account_id IN (?)
        AND transaction_type = 'transfer' 
        AND description = 'Credit card debt repayment to Alice Tan'
    `;

    db.query(repaymentQuery, [accountIds], (err2, result) => {
      if (err2) {
        console.error("SQL error:", err2);
        return res.status(500).send("Failed to calculate credit repayments");
      }

      const totalRepaid = result[0].total_repaid || 0;
      const creditLimit = 2000;
      const creditRemaining = Math.max(creditLimit - totalRepaid, 0);

    res.render("pay-bank", { 
  accounts, 
  creditRemaining // don't call toFixed here
});
    });
  });
});

app.post('/pay-bank', (req, res) => {
  const user = req.session.user;
  if (!user) return res.redirect('/login/customer-login');

  const { from_account_id, amount } = req.body;
  const payAmount = parseFloat(amount);
  const toAccountId = 2; // Alice Tan's fixed recipient
  const description = 'Credit card debt repayment to Alice Tan';

  if (!from_account_id || isNaN(payAmount) || payAmount <= 0) {
    return res.status(400).send('Invalid input.');
  }

  db.beginTransaction(err => {
    if (err) {
      console.error('❌ Failed to start DB transaction:', err);
      return res.status(500).send('Failed to start transaction.');
    }

    // Step 1: Get sender account info
    const getSenderSql = `
      SELECT a.*, u.email, u.full_name
      FROM accounts a
      JOIN users u ON a.user_id = u.user_id
      WHERE a.account_id = ?
    `;

    db.query(getSenderSql, [from_account_id], (err1, senderResults) => {
      if (err1 || senderResults.length === 0) {
        return db.rollback(() => res.status(500).send('Sender account not found.'));
      }

      const sender = senderResults[0];
      if (parseFloat(sender.balance) < payAmount) {
        return db.rollback(() => res.status(400).send('Insufficient account balance.'));
      }

      // Step 2: Deduct from sender account
      const deductSql = `UPDATE accounts SET balance = balance - ? WHERE account_id = ?`;
      db.query(deductSql, [payAmount, from_account_id], err2 => {
        if (err2) {
          return db.rollback(() => res.status(500).send('Failed to deduct.'));
        }

        // Step 3: Credit Alice's account
        const creditSql = `UPDATE accounts SET balance = balance + ? WHERE account_id = ?`;
        db.query(creditSql, [payAmount, toAccountId], err3 => {
          if (err3) {
            return db.rollback(() => res.status(500).send('Failed to credit Alice.'));
          }

          // Step 4: If debit/credit account, also deduct card balance
          const updateCardBalance = (next) => {
            if (['credit_account', 'debit_account'].includes(sender.account_type)) {
              const updateCardSql = `
                UPDATE cards
                SET balance = balance - ?
                WHERE account_id = ? AND card_status = 'active'
              `;
              db.query(updateCardSql, [payAmount, from_account_id], (err4) => {
                if (err4) {
                  console.warn('⚠️ Card not updated:', err4);
                  return db.rollback(() => res.status(500).send('Failed to update card balance.'));
                }
                next();
              });
            } else {
              next();
            }
          };

          // Step 5: Insert into transactions
          const insertTx = () => {
            const insertSql = `
              INSERT INTO transactions (account_id, transaction_type, amount, description)
              VALUES (?, 'transfer', ?, ?)
            `;
            db.query(insertSql, [from_account_id, payAmount, description], (err5) => {
              if (err5) {
                return db.rollback(() => res.status(500).send('Failed to log transaction.'));
              }

              // Step 6: Commit everything
              db.commit(err6 => {
                if (err6) {
                  return db.rollback(() => res.status(500).send('Commit failed.'));
                }                // ✅ Step 7: Send email
                sendEmail(
                  sender.email,
                  "Credit Card Repayment Successful",
                  `Hello ${sender.full_name},<br><br>You have successfully repaid <strong>$${payAmount.toFixed(2)}</strong> of your credit card debt.<br><br>Thank you for using RP Digital Bank.`
                );                // Redirect to success page
                res.render('payment-success', {
                  title: 'Payment Successful!',
                  message: 'Your credit card debt repayment has been processed successfully.',
                  amount: payAmount.toFixed(2),
                  accountType: sender.account_type.replace('_', ' '),
                  senderName: sender.full_name,
                  paymentDetails: {
                    title: 'Payment Details',
                    recipient: 'Alice Tan',
                    type: 'Credit Card Debt Repayment',
                    reference: `PAY-${Date.now()}`
                  },
                  creditRemaining: null, // Will be calculated separately if needed
                  redirectUrl: '/my-products',
                  redirectText: 'View My Products'
                });
              });
            });
          };

          updateCardBalance(insertTx);
        });
      });
    });
  });
});

//send money to paypal
// 🌐 Route: Render the Send Money page
app.get('/paypal-send', (req, res) => {
  const userId = req.session.user?.user_id;
  if (!userId) return res.redirect('/login/customer-login');

  const sql = 'SELECT * FROM accounts WHERE user_id = ? AND account_status = "active"';
  db.query(sql, [userId], (err, accounts) => {
    if (err) {
      console.error('Error fetching accounts:', err);
      return res.status(500).send('Internal Server Error');
    }

    res.render('paypal-send', { accounts });
  });
});

app.post('/paypal-spend', (req, res) => {
  const { account_id, amount } = req.body;

  if (!account_id || !amount || isNaN(amount)) {
    return res.status(400).send('Invalid request');
  }

  const parsedAmount = parseFloat(amount);
  if (parsedAmount <= 0) {
    return res.status(400).send('Amount must be greater than 0');
  }

  db.beginTransaction(err => {
    if (err) return res.status(500).send('Failed to start transaction');

    // 1. Get account + user info
    const getAccountSql = `
      SELECT a.account_id, a.account_type, u.user_id, u.email, u.full_name
      FROM accounts a
      JOIN users u ON a.user_id = u.user_id
      WHERE a.account_id = ?
    `;

    db.query(getAccountSql, [account_id], (accErr, accResults) => {
      if (accErr || accResults.length === 0) {
        return db.rollback(() => res.status(500).send('Account not found'));
      }

      const account = accResults[0];

      // 2. Deduct balance from accounts
      const updateAccountSql = `UPDATE accounts SET balance = balance - ? WHERE account_id = ?`;
      db.query(updateAccountSql, [parsedAmount, account.account_id], (acctErr) => {
        if (acctErr) return db.rollback(() => res.status(500).send('Failed to update account'));

        // 3. Deduct from card if needed
        const updateCardIfNeeded = (next) => {
          if (['credit_account', 'debit_account'].includes(account.account_type)) {
            const updateCardSql = `
              UPDATE cards
              SET balance = COALESCE(balance, 0) - ?
              WHERE account_id = ? AND card_status = 'active'
            `;
            db.query(updateCardSql, [parsedAmount, account.account_id], (cardErr) => {
              if (cardErr) return db.rollback(() => res.status(500).send('Card update failed'));
              next();
            });
          } else {
            next();
          }
        };

        // 4. Log transaction
        const insertTransaction = () => {
          const insertTxSql = `
            INSERT INTO transactions (account_id, transaction_type, amount, description)
            VALUES (?, 'spending', ?, 'Sent money via PayPal')
          `;
          db.query(insertTxSql, [account.account_id, parsedAmount], (txErr) => {
            if (txErr) return db.rollback(() => res.status(500).send('Transaction log failed'));

            // 5. Commit & send email
            db.commit(commitErr => {
              if (commitErr) {
                console.error('Commit failed:', commitErr);
                return db.rollback(() => res.status(500).send('Failed to commit transaction'));
              }

              // ✅ Send email
              sendEmail(
                account.email,
                "Spending Successful",
                `Hi ${account.full_name}, you have successfully spent $${parsedAmount.toFixed(2)} using your HOH Bank account via PayPal.`
              );

              res.status(200).send('Spending successful' + (account.account_type.includes('account') ? ' + card' : ''));
            });
          });
        };

        updateCardIfNeeded(insertTransaction);
      });
    });
  });
});

// Transfer Route
app.get('/transfer', (req, res) => {
  const userId = req.session.user?.user_id;
  if (!userId) return res.redirect('/login/customer-login');
  const sql = `
  SELECT account_id, account_type, balance, product_name
  FROM accounts
  JOIN product_catalog ON accounts.product_id = product_catalog.product_id
  WHERE user_id = ? AND account_status = 'active'
`;


  db.query(sql, [userId], (err, accounts) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }
    res.render('transfer', { accounts });
  });
});
app.post('/transfer', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login/customer-login');
  }

  const user = req.session.user;
  const {
    from_account_id,
    to_account_type,
    recipient_full_name,
    recipient_account_number,
    amount
  } = req.body;

  const transferAmount = parseFloat(amount);

  if (
    !from_account_id ||
    !to_account_type ||
    !recipient_full_name ||
    !recipient_account_number ||
    isNaN(transferAmount) ||
    transferAmount <= 0
  ) {
    return res.status(400).send("Invalid input data.");
  }

  // Get sender account and verify ownership + active status
  const getSenderAccountSql = `SELECT * FROM accounts WHERE account_id = ? AND user_id = ? AND account_status = 'active'`;
  db.query(getSenderAccountSql, [from_account_id, user.user_id], (senderErr, senderResults) => {
    if (senderErr) return res.status(500).send("Database error.");
    if (senderResults.length === 0) return res.status(400).send("Sender account not found or inactive.");

    const senderAccount = senderResults[0];

    if (senderAccount.balance < transferAmount) {
      return res.status(400).send("Insufficient funds in sender's account.");
    }

    // Get recipient account matching details and active status
    const getRecipientSql = `
      SELECT * FROM accounts
      WHERE full_name = ? AND account_number = ? AND account_type = ? AND account_status = 'active'
      LIMIT 1
    `;

    db.query(getRecipientSql, [recipient_full_name, recipient_account_number, to_account_type], (recipientErr, recipientResults) => {
      if (recipientErr) return res.status(500).send("Database error.");
      if (recipientResults.length === 0) {
        return res.send(`<script>alert('Recipient account not found.'); window.history.back();</script>`);
      }

      const recipientAccount = recipientResults[0];

      db.beginTransaction(txErr => {
        if (txErr) return res.status(500).send("Failed to start transaction.");

        // Deduct sender account balance
        const deductSql = `UPDATE accounts SET balance = balance - ? WHERE account_id = ?`;
        db.query(deductSql, [transferAmount, senderAccount.account_id], err2 => {
          if (err2) {
            return db.rollback(() => res.status(500).send("Failed to deduct from sender."));
          }

          // Add recipient account balance
          const addSql = `UPDATE accounts SET balance = balance + ? WHERE account_id = ?`;
          db.query(addSql, [transferAmount, recipientAccount.account_id], err3 => {
            if (err3) {
              return db.rollback(() => res.status(500).send("Failed to credit Alice."));
            }

            // Insert sender transaction log (negative amount)
            const insertTransactionSql = `
              INSERT INTO transactions (account_id, transaction_type, amount, description)
              VALUES (?, 'transfer', ?, ?)
            `;
            db.query(insertTransactionSql, [senderAccount.account_id, -transferAmount, `Transfer to ${recipient_full_name} (${recipient_account_number})`], (tx1Err) => {
              if (tx1Err) {
                return db.rollback(() => res.status(500).send("Failed to log sender transaction."));
              }

              // Insert recipient transaction log (positive amount)
              db.query(insertTransactionSql, [recipientAccount.account_id, transferAmount, `Transfer from ${user.full_name} (${senderAccount.account_number})`], (tx2Err) => {
                if (tx2Err) {
                  return db.rollback(() => res.status(500).send("Failed to log recipient transaction."));
                }

                // Function to update cards balances if applicable
                const updateCardBalanceIfNeeded = () => {
                  const tasks = [];

                  // Deduct from sender's card if credit or debit account
                  if (["credit_account", "debit_account"].includes(senderAccount.account_type)) {
                    tasks.push(new Promise((resolve, reject) => {
                      const deductSenderCardSql = `
                        UPDATE cards 
                        SET balance = balance - ? 
                        WHERE account_id = ? AND card_status = 'active'
                      `;
                      db.query(deductSenderCardSql, [transferAmount, senderAccount.account_id], (err) => {
                        if (err) return reject("Failed to deduct from sender's card.");
                        resolve();
                      });
                    }));
                  }

                  // Add to recipient's card if credit or debit account
                  if (["credit_account", "debit_account"].includes(recipientAccount.account_type)) {
                    tasks.push(new Promise((resolve, reject) => {
                      const creditRecipientCardSql = `
                        UPDATE cards 
                        SET balance = balance + ? 
                        WHERE account_id = ? AND card_status = 'active'
                      `;
                      db.query(creditRecipientCardSql, [transferAmount, recipientAccount.account_id], (err) => {
                        if (err) return reject("Failed to credit recipient's card.");
                        resolve();
                      });
                    }));
                  }

                  // Run all card updates
                  Promise.all(tasks)
                    .then(() => finalizeTransfer())
                    .catch(errorMsg => db.rollback(() => res.status(500).send(errorMsg)));
                };

                // Commit transaction and send response & emails
                const finalizeTransfer = () => {
                  db.commit(commitErr => {
                    if (commitErr) {
                      return db.rollback(() => res.status(500).send("Failed to commit transaction."));
                    }                    Promise.all([
                      sendEmail(user.email, "Transfer Sent", `You have successfully transferred $${transferAmount.toFixed(2)} to ${recipient_full_name}.`),
                      sendEmail(recipientAccount.email || 'recipient@example.com', "Transfer Received", `You have received $${transferAmount.toFixed(2)} from ${user.full_name}.`)
                    ]).catch(err => console.error("Email error:", err));

                    // Redirect to success page
                    res.render('transfer-success', {
                      amount: transferAmount.toFixed(2),
                      recipientName: recipient_full_name,
                      accountType: to_account_type.replace('_', ' '),
                      senderName: user.full_name
                    });
                  });
                };

                updateCardBalanceIfNeeded();
              });
            });
          });
        });
      });
    });
  });
});
app.get('/my-products', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login/customer-login');
  }

  const user = req.session.user;
  const userId = user.user_id;

  const accountQuery = `
    SELECT a.*, p.product_name 
    FROM accounts a
    JOIN product_catalog p ON a.product_id = p.product_id
    WHERE a.user_id = ?
  `;

  const cardQuery = `
    SELECT c.*, p.product_name 
    FROM cards c
    JOIN product_catalog p ON c.product_id = p.product_id
    WHERE c.user_id = ?
  `;

  db.query(accountQuery, [userId], (err, accounts) => {
    if (err) {
      console.error('Error fetching accounts:', err);
      return res.status(500).send('Failed to retrieve accounts');
    }

    db.query(cardQuery, [userId], (err2, cards) => {
      if (err2) {
        console.error('Error fetching cards:', err2);
        return res.status(500).send('Failed to retrieve cards');
      }

      // ✅ Check if user has credit_account
      const hasCreditAccount = accounts.some(acc => acc.account_type === 'credit_account');

      // ✅ Calculate how much user has repaid so far
      const getPaidQuery = `
        SELECT SUM(amount) AS totalPaid
        FROM transactions
        WHERE account_id IN (
          SELECT account_id FROM accounts WHERE user_id = ?
        )
        AND transaction_type = 'transfer'
        AND description = 'Credit card debt repayment to Alice Tan'
      `;

      db.query(getPaidQuery, [userId], (err3, result) => {
        if (err3) {
          console.error('Error calculating credit repayments:', err3);
          return res.status(500).send('Failed to calculate repayments');
        }

        const totalPaid = result[0].totalPaid || 0;
        const creditRemaining = 2000 - totalPaid;

        res.render('my-products', {
          user,
          accounts,
          cards,
          hasCreditAccount,
          creditRemaining
        });
      });
    });
  });
});

// Debit Card Application Route
app.post('/submit-card-application', upload.single('student_id'), (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login/customer-login');
  }

  const user = req.session.user;

  // DEBUG logs to verify form and file
  console.log('Form data:', req.body);
  console.log('Uploaded file:', req.file);

  const {
    nationality = '',
    income_source = 0.00,
    address = ''
  } = req.body || {};

  const student_id_upload_path = req.file ? req.file.path : '';

  const dob = new Date(user.date_of_birth).toISOString().split('T')[0];
  const productId = 1; // Debit Card Product

  const query = `
    INSERT INTO card_applications 
      (user_id, product_id, full_name, email, phone_number, date_of_birth, nric, nationality, income_source, address, student_id_upload_path, card_type, status, kyc_verified, submitted_at) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'debit', 'pending', false, NOW())
  `;

  const values = [
    user.user_id,
    productId,
    user.full_name,
    user.email,
    user.phone_number,
    dob,
    user.nric,
    nationality,
    income_source,
    address,
    student_id_upload_path
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('DB insert error:', err);
      return res.status(500).send('Internal Server Error');
    }    sendConfirmationEmail(user.email, user.full_name)
      .then(() => {
        res.render('process-confirmation', {
          application: {
            full_name: user.full_name,
            email: user.email,
            phone_number: user.phone_number,
            card_type: 'Debit Card',
            status: 'pending',
            application_id: result.insertId
          },
          emailSent: true,
          message: 'Debit Card Application Submitted Successfully!'
        });
      })
      .catch((emailErr) => {
        console.error('Email sending failed:', emailErr);
        res.render('process-confirmation', {
          application: {
            full_name: user.full_name,
            email: user.email,
            phone_number: user.phone_number,
            card_type: 'Debit Card',
            status: 'pending',
            application_id: result.insertId
          },
          emailSent: false,
          message: 'Debit Card Application Submitted! However, we were unable to send the confirmation email.'
        });
      });
  });
});

app.post('/submit-credit-application', upload.single('student_id'), (req, res) => {
  console.log('Form body:', req.body);      // ⬅️ This should NOT be undefined
  console.log('Uploaded file:', req.file);  // ⬅️ This should show file info

  if (!req.session.user) {
    return res.redirect('/login/customer-login');
  }

  const user = req.session.user;

  const {
    nationality = '',
    income_source = 0.00,
    address = ''
  } = req.body || {};

  const student_id_upload_path = req.file ? req.file.path : '';

  const dob = new Date(user.date_of_birth).toISOString().split('T')[0];
  const productId = 2; // Credit Card

  const query = `
    INSERT INTO card_applications 
    (user_id, product_id, full_name, email, phone_number, date_of_birth, nric, nationality, income_source, address, student_id_upload_path, card_type, status, kyc_verified, submitted_at) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'credit', 'pending', false, NOW())
  `;

  const values = [
    user.user_id,
    productId,
    user.full_name,
    user.email,
    user.phone_number,
    dob,
    user.nric,
    nationality,
    income_source,
    address,
    student_id_upload_path
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('DB insert error:', err);
      return res.status(500).send('Internal Server Error');
    }    sendConfirmationEmail(user.email, user.full_name)
      .then(() => {
        res.render('process-confirmation', {
          application: {
            full_name: user.full_name,
            email: user.email,
            phone_number: user.phone_number,
            card_type: 'Credit Card',
            status: 'pending',
            application_id: result.insertId
          },
          emailSent: true,
          message: 'Credit Card Application Submitted Successfully!'
        });
      })
      .catch((emailErr) => {
        console.error('Email sending failed:', emailErr);
        res.render('process-confirmation', {
          application: {
            full_name: user.full_name,
            email: user.email,
            phone_number: user.phone_number,
            card_type: 'Credit Card',
            status: 'pending',
            application_id: result.insertId
          },
          emailSent: false,
          message: 'Credit Card Application Submitted! However, we were unable to send the confirmation email.'
        });
      });
  });
});


app.post('/submit-application', (req, res) => {
  console.log(req.body); // to debug
  res.send('Application received.');
});

//cancel card
app.get('/cancel-card/:accountNumber', (req, res) => {
  const accountNumber = req.params.accountNumber;

  const sql = `SELECT * FROM accounts WHERE account_number = ?`;

  db.query(sql, [accountNumber], (err, results) => {
    if (err) {
      console.error('❌ DB error:', err);
      return res.status(500).send('Database error.');
    }

    if (results.length === 0) {
      return res.status(404).send('Account not found.');
    }

    const account = results[0]; // ✅ Now account is defined

    res.render('cancel-card-page', {
      accountNumber,
      error: null,
      success: null,
      otpSent: false,
      balance: account.balance
    });
  });
});

app.post('/send-cancel-otp', (req, res) => {
  const { account_number } = req.body;

  const sql = `
    SELECT users.email FROM accounts 
    JOIN users ON accounts.user_id = users.user_id 
    WHERE account_number = ?
  `;

  db.query(sql, [account_number], (err, results) => {
    if (err || results.length === 0) {
      return res.render('cancel-card-page', {
        accountNumber: account_number,
        error: "Email not found.",
        success: null,
        otpSent: false
      });
    }

    const email = results[0].email;
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP

    // ✅ Changed 'account_cancel' → 'card_cancel'
    db.query(
      'INSERT INTO otp_requests (user_id, purpose, otp_code, created_at, expires_at) VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
      [req.session.user.user_id, 'card_cancel', otp],
      (otpErr) => {
        if (otpErr) {
          console.error('❌ Failed to store OTP:', otpErr);
          return res.render('cancel-card-page', {
            accountNumber: account_number,
            error: 'Failed to send OTP. Please try again.',
            success: null,
            otpSent: false
          });
        }

        // Send OTP email
        sendEmail(email, 'Your OTP Code', `Your OTP code is: ${otp}. It is valid for 10 minutes.`)
          .then(() => {
            res.render('cancel-card-page', {
              accountNumber: account_number,
              error: null,
              success: 'OTP has been sent to your email.',
              otpSent: true,
              balance: null
            });
          })
          .catch(emailErr => {
            console.error('❌ Failed to send OTP email:', emailErr);
            res.render('cancel-card-page', {
              accountNumber: account_number,
              error: 'Failed to send OTP. Please try again.',
              success: null,
              otpSent: false,
              balance: null
            });
          });
      }
    );
  });
});

app.post('/confirm-cancel-card', (req, res) => {
  const { account_number, confirm_text, otp } = req.body;

  if (confirm_text.trim().toLowerCase() !== 'cancel account') {
    return res.render('cancel-card-page', {
      accountNumber: account_number,
      error: 'You must type "cancel account" to confirm cancellation.',
      success: null,
      otpSent: true
    });
  }

  const findCardSql = `
    SELECT c.card_number
    FROM cards c
    JOIN accounts a ON c.account_id = a.account_id
    WHERE a.account_number = ? AND c.card_status = 'active'
    LIMIT 1
  `;

  db.query(findCardSql, [account_number], (err, cardResults) => {
    if (err) {
      return res.render('cancel-card-page', {
        accountNumber: account_number,
        error: 'Database error when checking for card.',
        success: null,
        otpSent: true
      });
    }    const cancelAccount = () => {
      // First get the user details for email
      const getUserDetailsSql = `
        SELECT u.email, u.full_name, a.account_type, a.balance
        FROM accounts a
        JOIN users u ON a.user_id = u.user_id
        WHERE a.account_number = ?
      `;
      
      db.query(getUserDetailsSql, [account_number], (userErr, userResults) => {
        if (userErr || userResults.length === 0) {
          return res.render('cancel-card-page', {
            accountNumber: account_number,
            error: 'Failed to retrieve account details.',
            success: null,
            otpSent: true
          });
        }

        const userDetails = userResults[0];
        
        const updateAccountSql = `UPDATE accounts SET account_status = 'closed' WHERE account_number = ?`;
        db.query(updateAccountSql, [account_number], (accErr, accResult) => {
          if (accErr || accResult.affectedRows === 0) {
            return res.render('cancel-card-page', {
              accountNumber: account_number,
              error: 'Failed to close the account.',
              success: null,
              otpSent: true
            });
          }

          // ✅ Send account cancellation confirmation email
          const emailSubject = "Account Cancellation Confirmation - RP Digital Bank";
          const emailBody = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #dc3545;">Account Cancellation Confirmation</h2>
              
              <p>Dear ${userDetails.full_name},</p>
              
              <p>We confirm that your account has been successfully cancelled as requested.</p>
              
              <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h4>Account Details:</h4>
                <p><strong>Account Number:</strong> ${account_number}</p>
                <p><strong>Account Type:</strong> ${userDetails.account_type.replace('_', ' ').toUpperCase()}</p>
                <p><strong>Final Balance:</strong> $${parseFloat(userDetails.balance).toFixed(2)}</p>
                <p><strong>Cancellation Date:</strong> ${new Date().toLocaleDateString()}</p>
              </div>
              
              <div style="background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107; margin: 20px 0;">
                <p><strong>Important:</strong> This account is now permanently closed and cannot be reactivated. All associated cards have also been cancelled.</p>
              </div>
              
              <p>If you have any remaining balance, please contact our customer service team for assistance with fund retrieval.</p>
              
              <p>Thank you for banking with HOH. We're sorry to see you go and hope to serve you again in the future.</p>
              
              <hr style="margin: 30px 0; border: none; border-top: 1px solid #dee2e6;">
              
              <p style="color: #6c757d; font-size: 14px;">
                <strong>RP Digital Bank Customer Service</strong><br>
                Email: support@rpdigitalbank.com<br>
                Phone: +65 6XXX XXXX<br>
                <em>This is an automated message. Please do not reply to this email.</em>
              </p>
            </div>
          `;

          sendEmail(userDetails.email, emailSubject, emailBody)
            .then(() => {
              console.log(`✅ Account cancellation email sent to ${userDetails.email}`);
            })
            .catch((emailErr) => {
              console.error('❌ Failed to send cancellation email:', emailErr);
            });

          return res.render('cancel-card-page', {
            accountNumber: account_number,
            error: null,
            success: 'Your account has been successfully closed. A confirmation email has been sent to your registered email address.',
            otpSent: false
          });
        });
      });
    };

    if (cardResults.length === 0) {
      // No active card found — just close the account
      return cancelAccount();
    }

    // Active card found — cancel card first
    const cardNumber = cardResults[0].card_number;
    const updateCardSql = `UPDATE cards SET card_status = 'cancelled' WHERE card_number = ?`;

    db.query(updateCardSql, [cardNumber], (cardErr) => {
      if (cardErr) {
        return res.render('cancel-card-page', {
          accountNumber: account_number,
          error: 'Failed to cancel the account.',
          success: null,
          otpSent: true
        });
      }

      // Now close the account
      return cancelAccount();
    });
  });
});

//user transactions
app.get('/user-transactions', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer-login');

  const userId = req.session.user.user_id;
  const { filter, date } = req.query;

  let sql = `
    SELECT t.*, a.account_number, a.account_type
    FROM transactions t
    JOIN accounts a ON t.account_id = a.account_id
    WHERE a.user_id = ?
  `;
  const params = [userId];

  if (filter === 'today') {
    sql += ' AND DATE(t.transaction_date) = CURDATE()';
  } else if (filter === 'month') {
    sql += ' AND YEAR(t.transaction_date) = YEAR(CURDATE()) AND MONTH(t.transaction_date) = MONTH(CURDATE())';
  } else if (date && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
    sql += ' AND DATE(t.transaction_date) = ?';
    params.push(date);
  }

  sql += ' ORDER BY t.transaction_date DESC';

  db.query(sql, params, (err, transactions) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to fetch transactions.');
    }

    res.render('user-transactions', {
      user: req.session.user,
      transactions,
      filter: filter || '',
      selectedDate: date || ''
    });
  });
});
//staff transactions
app.get('/transactions', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.status(403).send("Access denied. Staff only.");
  }

  const selectedUserId = req.query.user_id;

  // Only fetch users with role = 'customer'
  const userListQuery = `SELECT user_id, full_name FROM users WHERE role = 'customer' ORDER BY full_name`;

  db.query(userListQuery, (userErr, users) => {
    if (userErr) {
      console.error(userErr);
      return res.status(500).send("Failed to fetch users.");
    }

    let sql = `
      SELECT t.*, a.account_number, a.account_type, u.full_name
      FROM transactions t
      JOIN accounts a ON t.account_id = a.account_id
      JOIN users u ON a.user_id = u.user_id
    `;
    const params = [];

    if (selectedUserId) {
      sql += ` WHERE u.user_id = ?`;
      params.push(selectedUserId);
    }

    sql += ` ORDER BY t.transaction_date DESC`;

    db.query(sql, params, (txErr, transactions) => {
      if (txErr) {
        console.error(txErr);
        return res.status(500).send("Failed to fetch transactions.");
      }

      res.render('transactions', {
        users,
        transactions,
        selectedUserId
      });
    });
  });
});

//Staff Card
app.get('/pending-card', (req, res) => {
  const query = "SELECT * FROM card_applications WHERE status = 'pending'";
  db.query(query, (err, results) => {
    if (err) {
      console.error("DB query error:", err);
      return res.status(500).send("Internal Server Error");
    }

    // Ensure income_source is a number to prevent EJS toFixed error
    const applications = results.map(app => ({
      ...app,
      income_source: parseFloat(app.income_source) || 0.00
    }));

    res.render('pending-card', { applications });
  });
});

app.post('/pending-card', (req, res) => {
  const { application_id, action, rejection_reason } = req.body;

  if (!['accept', 'reject'].includes(action)) {
    return res.redirect('/pending-card');
  }

  const getAppQuery = `SELECT * FROM card_applications WHERE application_id = ?`;
  db.query(getAppQuery, [application_id], (err, results) => {
    if (err || results.length === 0) {
      console.error(err || 'No application found');
      return res.status(500).send("Application not found or DB error");
    }

    const app = results[0];
    const newStatus = action === 'accept' ? 'approved' : 'rejected';
    const kyc = 1;

    const updateQuery = `UPDATE card_applications SET status = ?, kyc_verified = ? WHERE application_id = ?`;
    db.query(updateQuery, [newStatus, kyc, application_id], (updateErr) => {
      if (updateErr) {
        console.error(updateErr);
        return res.status(500).send("Failed to update status");
      }

      if (action === 'accept') {
        const cvv = generateCVV();
        const expiryDate = new Date();
        expiryDate.setFullYear(expiryDate.getFullYear() + 4);
        const formattedExpiry = expiryDate.toISOString().split('T')[0];
        const cardNumber = generateRandomNumber(9);
        const accountNumber = generateRandomNumber(9);
        const accountType = app.card_type === 'credit' ? 'credit_account' : 'debit_account';

        // ✅ Set initial balance: 2000 if credit, 0 if debit
        const initialBalance = app.card_type === 'credit' ? 2000.00 : 0.00;

        // Step 1: Create account
        const insertAccountQuery = `
          INSERT INTO accounts (user_id, product_id, full_name, account_number, account_type, balance, account_status)
          VALUES (?, ?, ?, ?, ?, ?, 'active')
        `;
        db.query(insertAccountQuery, [
          app.user_id,
          app.product_id,
          app.full_name,
          accountNumber,
          accountType,
          initialBalance
        ], (accErr, accResult) => {
          if (accErr) {
            console.error('Insert account error:', accErr);
            return res.status(500).send("Failed to create account");
          }

          const accountId = accResult.insertId;

          // Step 2: Create card with same balance
          const insertCardQuery = `
            INSERT INTO cards 
            (user_id, product_id, account_id, full_name, card_number, card_type, expiry_date, cvv, balance, card_status, issued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NOW())
          `;
          db.query(insertCardQuery, [
            app.user_id,
            app.product_id,
            accountId,
            app.full_name,
            cardNumber,
            app.card_type,
            formattedExpiry,
            cvv,
            initialBalance
          ], (cardErr) => {
            if (cardErr) {
              console.error('Insert card error:', cardErr);
              return res.status(500).send("Failed to issue card");
            }

            sendApprovalEmail(app.email, app.full_name)
              .then(() => res.redirect('/pending-card'))
              .catch(emailErr => {
                console.error('Email failed:', emailErr);
                res.redirect('/pending-card');
              });
          });
        });
      } else {
        const reasonText = rejection_reason || "No reason provided";
        sendRejectionEmail(app.email, app.full_name, reasonText)
          .then(() => res.redirect('/pending-card'))
          .catch(emailErr => {
            console.error('Rejection email failed:', emailErr);
            res.redirect('/pending-card');
          });
      }
    });
  });
});

app.get('/viewAccepted', (req, res) => {
  const query = "SELECT * FROM card_applications WHERE status = 'approved'";
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Server error");
    }
    res.render('viewAccepted', { apps: results });
  });
});

app.get('/viewRejected', (req, res) => {
  const query = "SELECT * FROM card_applications WHERE status = 'rejected'";
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Server error");
    }
    res.render('viewRejected', { apps: results });
  });
});



app.get('/kyc/:user_id', (req, res) => {
  const userId = req.params.user_id;
  const query = 'SELECT * FROM users WHERE user_id = ?';

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server error');
    }

    if (results.length === 0) {
      return res.status(404).send('User not found');
    }

    res.render('kyc', { user: results[0] });
  });
});
app.get('/credit-card', (req, res) => {
  const user = req.session.user; // use the whole session user object

  if (!user) {
    return res.redirect('/login/customer'); // adjust this path if needed
  }

  const query = 'SELECT * FROM users WHERE user_id = ?';

  db.query(query, [user.user_id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Database error');
    }

    if (results.length === 0) {
      return res.status(404).send('User not found');
    }

    const userData = results[0];
    res.render('credit-card', { user: userData });
  });
});
app.get('/cards', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const searchQuery = req.query.search || '';
  const statusFilter = req.query.status || '';
  
  let query = `
    SELECT c.*, u.email, u.full_name, u.phone_number
    FROM cards c
    JOIN users u ON c.user_id = u.user_id
    WHERE u.role = 'customer'
  `;
  
  let params = [];
  let whereConditions = [];

  if (searchQuery) {
    whereConditions.push(`(u.full_name LIKE ? OR c.card_number LIKE ? OR c.card_type LIKE ? OR u.email LIKE ?)`);
    const likeQuery = `%${searchQuery}%`;
    params.push(likeQuery, likeQuery, likeQuery, likeQuery);
  }

  if (statusFilter) {
    whereConditions.push(`c.card_status = ?`);
    params.push(statusFilter);
  }

  if (whereConditions.length > 0) {
    query += ` AND ${whereConditions.join(' AND ')}`;
  }

  query += ` ORDER BY c.issued_at DESC`;

  db.query(query, params, (err, results) => {
    if (err) {
      console.error("Error fetching card data:", err);
      return res.status(500).send("Internal Server Error");
    }
    res.render('cards', { 
      cards: results,
      searchQuery,
      statusFilter 
    });
  });
});

// CSV Export route for cards
app.get('/export/cards', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  try {
    const [cards] = await db.promise().query(`
      SELECT 
        c.card_id,
        c.user_id,
        u.full_name,
        u.email,
        u.phone_number,
        u.nric,
        c.card_number,
        c.card_type,
        c.cvv,
        c.balance,
        c.expiry_date,
        c.card_status,
        c.issued_at
      FROM cards c
      JOIN users u ON c.user_id = u.user_id
      ORDER BY c.issued_at DESC
    `);

    if (cards.length === 0) {
      return res.status(404).send('No cards found to export');
    }

    // Define CSV fields
    const fields = [
      { label: 'Card ID', value: 'card_id' },
      { label: 'User ID', value: 'user_id' },
      { label: 'Full Name', value: 'full_name' },
      { label: 'Email', value: 'email' },
      { label: 'Phone Number', value: 'phone_number' },
      { label: 'NRIC', value: 'nric' },
      { label: 'Card Number', value: 'card_number' },
      { label: 'Card Type', value: 'card_type' },
      { label: 'CVV', value: 'cvv' },
      { label: 'Balance', value: 'balance' },
      { label: 'Expiry Date', value: 'expiry_date' },
      { label: 'Card Status', value: 'card_status' },
      { label: 'Issued At', value: 'issued_at' }
    ];

    // Format data for CSV
    const formattedCards = cards.map(card => ({
      ...card,
      card_type: card.card_type.replace('_', ' ').toUpperCase(),
      card_status: card.card_status.toUpperCase(),
      balance: parseFloat(card.balance || 0).toFixed(2),
      expiry_date: card.expiry_date ? new Date(card.expiry_date).toLocaleDateString() : 'N/A',
      issued_at: card.issued_at ? new Date(card.issued_at).toLocaleString() : 'N/A',
      email: card.email || 'N/A',
      phone_number: card.phone_number || 'N/A',
      nric: card.nric || 'N/A'
    }));

    const parser = new Parser({ fields });
    const csv = parser.parse(formattedCards);

    // Set headers for file download
    const filename = `cards_export_${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.send(csv);
  } catch (err) {
    console.error('Error exporting cards:', err);
    res.status(500).send('Failed to export cards data');
  }
});

function sendConfirmationEmail(toEmail, fullName) {
  const mailOptions = {
    from: 'TheOfficalHOH@gmail.com',
    to: toEmail,
    subject: 'HOH Bank - Card Application Received',
    html: `
      <h3>Dear ${fullName},</h3>
      <p>Thank you for applying for a HOH Debit/Credit Card. Your application is currently being processed and is marked as <strong>Pending</strong>.</p>
      <p>You will be notified via email once it has been reviewed.</p>
      <br/>
      <p>Best regards,<br>HOH Bank Team</p>
    `,
  };

  return transporter.sendMail(mailOptions);
}
// Utility: Random 3-digit CVV
function generateCVV() {
  return Math.floor(100 + Math.random() * 900).toString();
}

// ✅ Approval Email Function
function sendApprovalEmail(email, name) {
  return sendEmail(email, 'HOH Card Application Approved', `
    <h3>Dear ${name},</h3>
    <p>Congratulations! Your card application has been <strong>approved</strong>.</p>
    <p>Your HOH card will be issued and activated shortly.</p>
    <br/>
    <p>Best regards,<br>HOH Bank Team</p>
  `);
}

function sendRejectionEmail(email, name, reason) {
  return sendEmail(email, 'HOH Card Application Rejected', `
    <h3>Dear ${name},</h3>
    <p>We regret to inform you that your card application has been <strong>rejected</strong>.</p>
    <p><strong>Reason:</strong> ${reason}</p>
    <p>If you have questions or need assistance, feel free to contact our support team.</p>
    <br/>
    <p>Best regards,<br>HOH Bank Team</p>
  `);
}

function generateCardNumber() {
  let number = '';
  for (let i = 0; i < 16; i++) {
    number += Math.floor(Math.random() * 10).toString();
  }
  return number;
}

function generateRandomNumber(length) {
  let number = '';
  for (let i = 0; i < length; i++) {
    number += Math.floor(Math.random() * 10);
  }
  return number;
}

//OTP for User to delete account
app.post('/request-account-otp', (req, res) => {
  const { account_number } = req.body;

  const accountQuery = `
    SELECT a.account_id, a.user_id, a.full_name, u.email, a.balance
    FROM accounts a
    JOIN users u ON a.user_id = u.user_id
    WHERE a.account_number = ?
  `;

  db.query(accountQuery, [account_number], (err, results) => {
    if (err || results.length === 0) {
      console.error('❌ Account lookup failed:', err);
      return res.status(404).send('Account not found.');
    }

    const account = results[0];
    const otp = Math.floor(100000 + Math.random() * 900000);
    const expiry = new Date(Date.now() + 10 * 60 * 1000); // 10 mins from now

    // Clean up any existing OTPs for the same purpose
    const cleanupSql = `DELETE FROM otp_requests WHERE user_id = ? AND purpose = 'account_cancel'`;
    db.query(cleanupSql, [account.user_id], (cleanupErr) => {
      if (cleanupErr) {
        console.error('❌ Failed to clean up existing OTPs:', cleanupErr);
      }

      // Insert new OTP
      const insertOtp = `
        INSERT INTO otp_requests (user_id, otp_code, purpose, created_at, expires_at)
        VALUES (?, ?, 'account_cancel', NOW(), ?)
      `;
      db.query(insertOtp, [account.user_id, otp, expiry], (otpErr) => {
        if (otpErr) {
          console.error('❌ Failed to insert OTP:', otpErr);
          return res.status(500).send('Failed to create OTP.');
        }

        // Send OTP email
        sendEmail(account.email, 'Your OTP Code', `Your OTP code is: ${otp}. It is valid for 10 minutes.`)
          .then(() => {
            res.render('cancel-account-page', {
              accountNumber: account_number,
              error: null,
              success: 'OTP sent to your email address.',
              otpSent: true,
              balance: null
            });
          })
          .catch(emailErr => {
            console.error('❌ Failed to send OTP email:', emailErr);
            res.render('cancel-account-page', {
              accountNumber: account_number,
              error: 'Failed to send OTP. Please try again.',
              success: null,
              otpSent: false,
              balance: null
            });
          });
      });
    });
  });
});


//OTP Verification for Account Cancellation
app.post('/verify-account-cancel', (req, res) => {
  const { account_number, otp_code } = req.body;

  const accountQuery = `
    SELECT a.account_id, a.user_id, a.account_type, u.email, u.full_name, a.balance
    FROM accounts a
    JOIN users u ON a.user_id = u.user_id
    WHERE a.account_number = ?
  `;

  db.query(accountQuery, [account_number], (err, accounts) => {
    if (err || accounts.length === 0) {
      console.error('❌ Account not found or error:', err);
      return res.status(404).send('Account not found.');
    }

    const account = accounts[0];
    const now = new Date();

    const otpQuery = `
      SELECT * FROM otp_requests 
      WHERE user_id = ? AND otp_code = ? AND purpose = 'account_cancel' AND expires_at > ?
    `;

    db.query(otpQuery, [account.user_id, otp_code, now], (otpErr, otps) => {
      if (otpErr || otps.length === 0) {
        return res.render('cancel-account-page', {
          accountNumber: account_number,
          error: 'Invalid or expired OTP.',
          success: null,
          otpSent: true,
          balance: account.balance
        });
      }

      // Delete the account
      db.query(`DELETE FROM accounts WHERE account_id = ?`, [account.account_id], (delErr) => {
        if (delErr) {
          console.error('❌ Failed to delete account:', delErr);
          return res.status(500).send('Failed to cancel account.');
        }

        // Optional: Remove OTP after use
        db.query(`DELETE FROM otp_requests WHERE otp_id = ?`, [otps[0].otp_id]);

        sendConfirmationEmailStatus(account.email, account.full_name, account.account_type, 'Cancelled')
          .then(() => {
            res.redirect('/my-products');
          })
          .catch(emailErr => {
            console.error('❌ Failed to send cancellation email:', emailErr);
            res.redirect('/my-products');
          });
      });
    });
  });
});


//To view full account details of Users
app.get('/kyc-account/:application_id', (req, res) => {
  const id = req.params.application_id;

  const query = `
    SELECT * FROM account_applications 
    WHERE application_id = ?
  `;
  db.query(query, [id], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).send('Application not found');
    }

    const app = results[0];
    res.render('kyc-account', { app });
  });
});


// KYC card details route for viewing card application details
app.get('/kyc-card/:application_id', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }

  const applicationId = req.params.application_id;
  
  const query = `
    SELECT ca.*, u.created_at as user_created_at 
    FROM card_applications ca
    JOIN users u ON ca.user_id = u.user_id
    WHERE ca.application_id = ?
  `;
  
  db.query(query, [applicationId], (err, results) => {
    if (err) {
      console.error('KYC card query error:', err);
      return res.status(500).send('Database error');
    }
    
    if (results.length === 0) {
      return res.status(404).send('Card application not found');
    }
    
    const application = results[0];
    res.render('kyc', { 
      user: application,
      isCardApplication: true,
      application: application
    });
  });
});

// Add this route before the "Start server" comment

app.get('/account', async (req, res) => {
  const userId = req.params.userId;

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [userRows] = await connection.execute(
      'SELECT * FROM users WHERE user_id = ?',
      [userId]
    );

    if (userRows.length === 0) {
      return res.status(404).send('User not found');
    }

    const user = userRows[0];

    const [cardRows] = await connection.execute(
      'SELECT * FROM cards WHERE user_id = ?',
      [userId]
    );

    res.render('customer-account', {
      user,
      cards: cardRows,
    });

    await connection.end();
  } catch (err) {
    console.error('DB error:', err);
    res.status(500).send('Internal Server Error');
  }
});



app.get('/product-catalog', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    return res.redirect('/login/staff');
  }
  
  const [products] = await db.promise().query('SELECT * FROM product_catalog');
  res.render('product-catalog', { products });
});

//Alicia///////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////





// Financial Advisor (Bryan) /////////////////////////////////////////////////////

// Financial Advisor Consultation Email Routes

// Advisor Change Password OTP Email
function sendAdvisorOtpEmail(toEmail, advisorName, otpCode) {
  return sendEmail(
    toEmail,
    'HOH Bank - OTP for Password Change',
    `
      <h3>Dear ${advisorName},</h3>
      <p>You have requested to update your password on the HOH Bank platform.</p>
      <p>Please enter the following One-Time Password (OTP) to confirm the change:</p>
      <h2 style="color: #22c55e;">${otpCode}</h2>
      <p>This OTP is valid for 10 minutes only.</p>
      <p>If you did not make this request, please contact our support team immediately.</p>
      <br>
      <p>Thank you,<br>HOH Bank System</p>
    `
  );
}

// ✅ For Accept
function sendConsultationConfirmationEmail(toEmail, studentName, appointmentDate, videoLink) {
  return sendEmail(
    toEmail,
    'HOH Bank - Consultation Accepted',
    `
      <h3>Dear ${studentName},</h3>
      <p>Your consultation has been <strong>ACCEPTED</strong>.</p>
      <p>Appointment Date: <strong>${new Date(appointmentDate).toLocaleString()}</strong></p>
      <p>Please join the consultation using the link below:</p>
      <p><a href="${videoLink}" target="_blank">${videoLink}</a></p>
      <p>Thank you,<br>HOH Bank Team</p>
    `
  );
}

// ✅ For Reschedule
function sendRescheduleEmail(toEmail, studentName, newDate, videoLink) {
  return sendEmail(
    toEmail,
    'HOH Bank - Consultation Rescheduled',
    `
      <h3>Dear ${studentName},</h3>
      <p>Your consultation has been <strong>RESCHEDULED</strong>.</p>
      <p>New Appointment Date: <strong>${new Date(newDate).toLocaleString()}</strong></p>
      <p>Please join the consultation using the updated link below:</p>
      <p><a href="${videoLink}" target="_blank">${videoLink}</a></p>
      <p>Thank you,<br>HOH Bank Team</p>
    `
  );
}

// ✅ For Cancellation by Customer
function sendCancellationEmailToAdvisor(advisorEmail, studentName, appointmentDate) {
  return sendEmail(
    advisorEmail,
    'HOH Bank - Consultation Cancelled',
    `
      <h3>Dear Advisor,</h3>
      <p>The consultation with <strong>${studentName}</strong> scheduled on <strong>${new Date(appointmentDate).toLocaleString()}</strong> has been <strong>cancelled</strong> by the customer.</p>
      <br/>
      <p>Best regards,<br>HOH Bank Team</p>
    `
  );
}

// ✅ For Video Link to Advisor
function sendAdvisorVideoLinkEmail(toEmail, advisorName, studentName, appointmentDate, videoLink) {
  return sendEmail(
    toEmail,
    'HOH Bank - Consultation Accepted (Video Link)',
    `
      <h3>Dear ${advisorName},</h3>
      <p>You have successfully <strong>ACCEPTED</strong> a consultation with <strong>${studentName}</strong>.</p>
      <p>Appointment Date: <strong>${new Date(appointmentDate).toLocaleString()}</strong></p>
      <p>Here is the private video consultation link:</p>
      <p><a href="${videoLink}" target="_blank">${videoLink}</a></p>
      <p>Please keep this link confidential and only use it at the time of consultation.</p>
      <p>Thank you,<br>HOH Bank System</p>
    `
  );
}

// ✅ Notify Customer When Advisor Reschedules
function sendRescheduleNotificationToCustomer(toEmail, studentName, appointmentDate) {
  return sendEmail(
    toEmail,
    'HOH Bank - Consultation Rescheduled by Advisor',
    `
      <h3>Dear ${studentName},</h3>
      <p>Your financial advisor has <strong>rescheduled</strong> your consultation.</p>
      <p>New Appointment Date: <strong>${new Date(appointmentDate).toLocaleString()}</strong></p>
      <p>Please <a href="http://localhost:3000/login/customer">log in</a> to accept or cancel the new slot.</p>
      <p>If no action is taken, the consultation will remain in <strong>Pending Accept</strong> status.</p>
      <p>Thank you,<br>HOH Bank Team</p>
    `
  );
}


// Advisor Dahsboard route
app.get('/advisor/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login/advisor');
  const advisorId = req.session.user.user_id;
  const { search, status, date, month, year } = req.query;

  const selectedMonth = month || null;
  const selectedYear = year || new Date().getFullYear();

  let consultationsSql = `
    SELECT c.*, u.full_name AS student_name
    FROM consultations c
    LEFT JOIN users u ON c.customer_id = u.user_id
    WHERE (c.advisor_id = ? OR c.advisor_id IS NULL)
  `;
  const params = [advisorId];

  if (search) {
    consultationsSql += ` AND (u.full_name LIKE ?)`;
    params.push(`%${search}%`);
  }
  if (status) {
    consultationsSql += ` AND c.status = ?`;
    params.push(status);
  }
  if (date) {
    consultationsSql += ` AND DATE(c.appointment_date) = ?`;
    params.push(date);
  }

  consultationsSql += ` ORDER BY c.appointment_date DESC`;

  const completedCountSql = `
    SELECT COUNT(*) AS completedCount
    FROM consultations
    WHERE advisor_id = ? AND status = 'completed'
  `;

  const nextUpcomingSql = `
    SELECT c.*, u.full_name AS student_name
    FROM consultations c
    LEFT JOIN users u ON c.customer_id = u.user_id
    WHERE c.advisor_id = ? AND c.status IN ('booked', 'accepted')
    AND appointment_date > NOW()
    ORDER BY appointment_date ASC
    LIMIT 1
  `;

  const completedConsultationsSql = `
    SELECT c.*, u.full_name AS student_name
    FROM consultations c
    LEFT JOIN users u ON c.customer_id = u.user_id
    WHERE c.advisor_id = ? AND c.status = 'completed'
    ORDER BY c.appointment_date DESC
  `;

  const monthlyChartSql = `
    SELECT DAY(appointment_date) AS day, COUNT(*) AS count
    FROM consultations
    WHERE advisor_id = ? AND status = 'completed'
    AND MONTH(appointment_date) = ? AND YEAR(appointment_date) = ?
    GROUP BY day
  `;


  const yearlyChartSql = `
    SELECT MONTH(appointment_date) AS month, COUNT(*) AS count
    FROM consultations
    WHERE advisor_id = ? AND status = 'completed'
    AND YEAR(appointment_date) = ?
    GROUP BY month
  `;

  db.query(consultationsSql, params, (err, consultations) => {
    if (err) return errorRender('Failed to load consultations.');

    db.query(completedCountSql, [advisorId], (err2, completedResults) => {
      if (err2) return errorRender('Error fetching completed count');

      db.query(nextUpcomingSql, [advisorId], (err3, nextResult) => {
        if (err3) return errorRender('Error fetching next consultation');

        db.query(completedConsultationsSql, [advisorId], (err4, completedConsultations) => {
          if (err4) return errorRender('Error loading completed consultations');

          db.query(monthlyChartSql, [advisorId, selectedMonth, selectedYear], (err5, monthlyData) => {
            if (err5) return errorRender('Error loading monthly chart data');

            db.query(yearlyChartSql, [advisorId, selectedYear], (err6, yearlyData) => {
              if (err6) return errorRender('Error loading yearly chart data');

              const completedCount = completedResults[0].completedCount;
              const nextConsultation = nextResult.length > 0 ? nextResult[0] : null;

              const showingYearly = req.query.year && !req.query.month;



              res.render('advisor-dashboard', {
                consultations,
                completedConsultations,
                completedCount,
                nextConsultation,
                monthlyData,
                yearlyData,
                error: null,
                search,
                statusFilter: status,
                dateFilter: date,
                selectedMonth,
                selectedYear,
                showingYearly: !month,
              });
            });
          });
        });
      });
    });
  });

  function errorRender(message) {
    return res.render('advisor-dashboard', {
      consultations: [],
      completedConsultations: [],
      completedCount: 0,
      nextConsultation: null,
      monthlyData: [],
      yearlyData: [],
      error: message,
      search,
      statusFilter: status,
      dateFilter: date,
      selectedMonth,
      selectedYear,
      showingYearly: false 
    });
  }
});




// View Advisor's Upcoming Accepted Consultations
app.get('/advisor/myslots', (req, res) => {
  const advisorId = req.session.user?.user_id;

  const sql = `
    SELECT c.*, u.full_name AS student_name
    FROM consultations c
    LEFT JOIN users u ON c.customer_id = u.user_id
    WHERE c.advisor_id = ? AND c.status = 'accepted' AND c.customer_id IS NOT NULL
    ORDER BY c.appointment_date ASC
  `;

  db.query(sql, [advisorId], (err, results) => {
    if (err) {
      console.error(err);
      return res.render('advisor-myslots', {
        slots: [],
        error: 'Unable to load your upcoming consultations.'
      });
    }

    res.render('advisor-myslots', {
      slots: results,
      error: null
    });
  });
});


// Create Advisor Slot
app.post('/advisor/consultations/create', async (req, res) => {
  try {
    const advisorId = req.session.user?.user_id;
    const { appointment_date } = req.body;

    if (!advisorId || !appointment_date) {
      return res.status(400).send('Missing advisor ID or appointment date');
    }

    await db.promise().query(`
      INSERT INTO consultations (advisor_id, appointment_date, status)
      VALUES (?, ?, 'available')
    `, [advisorId, appointment_date]);

    res.redirect('/advisor/dashboard');
  } catch (err) {
    console.error('❌ Error creating slot:', err);
    res.status(500).send('Internal Server Error');
  }
});


// Accept Slot (Booked → Accepted)
app.post('/advisor/consultations/:id/accept', (req, res) => {
  if (!req.session.user) return res.redirect('/login/staff');

  const consultationId = req.params.id;
  const advisorName = req.session.user.full_name;
  const advisorEmail = req.session.user.email;

  const getSql = `
    SELECT c.appointment_date, u.email, u.full_name
    FROM consultations c
    LEFT JOIN users u ON c.customer_id = u.user_id
    WHERE c.consultation_id = ? AND c.status = 'booked'
  `;

  db.query(getSql, [consultationId], (err, results) => {
    if (err) {
      console.error(err);
      return res.redirect('/advisor/dashboard?error=fetch');
    }

    if (results.length === 0) {
      return res.redirect('/advisor/dashboard?error=nobooking');
    }

    const { appointment_date, email, full_name } = results[0];

    const videoLink = `https://meet.jit.si/hoh-${consultationId}-${Date.now()}`;

    const updateSql = `
      UPDATE consultations 
      SET status = 'accepted', was_accepted_before = TRUE, video_link = ?
      WHERE consultation_id = ?
    `;

    db.query(updateSql, [videoLink, consultationId], (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/advisor/dashboard?error=accept');
      }

      // ✅ Send to customer
      sendConsultationConfirmationEmail(email, full_name, appointment_date, videoLink)
        .then(() => {
          // ✅ Send to advisor
          return sendAdvisorVideoLinkEmail(advisorEmail, advisorName, full_name, appointment_date, videoLink);
        })
        .then(() => {
          res.redirect('/advisor/dashboard');
        })
        .catch((emailErr) => {
          console.error('Email failed:', emailErr);
          res.redirect('/advisor/dashboard?error=email');
        });
    });
  });
});


// Delete Slot
app.post('/advisor/consultations/:id/delete', (req, res) => {
  if (!req.session.user) return res.redirect('/login/staff');

  const consultationId = req.params.id;

  db.query(
    'DELETE FROM consultations WHERE consultation_id = ?',
    [consultationId],
    (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/advisor/dashboard?error=delete');
      }
      res.redirect('/advisor/dashboard');
    }
  );
});


// Reschedule Slot
app.post('/advisor/consultations/:id/reschedule', (req, res) => {
  if (!req.session.user) return res.redirect('/login/staff');

  const consultationId = req.params.id;
  const { new_date } = req.body;

  if (!new_date) {
    return res.status(400).send('Missing new date');
  }

  const videoLink = `https://meet.jit.si/hoh-${consultationId}-${Date.now()}`;

  // Get customer email and name to send notification
  const getInfoSql = `
    SELECT u.email AS student_email, u.full_name AS student_name
    FROM consultations c
    LEFT JOIN users u ON c.customer_id = u.user_id
    WHERE c.consultation_id = ?
  `;

  db.query(getInfoSql, [consultationId], (err, result) => {
    if (err) {
      console.error(err);
      return res.redirect('/advisor/dashboard?error=fetchinfo');
    }

    const { student_email, student_name } = result[0] || {};

    const updateSql = `
      UPDATE consultations 
      SET appointment_date = ?, status = 'pending accept', was_accepted_before = true, video_link = ?
      WHERE consultation_id = ?
    `;

    db.query(updateSql, [new_date, videoLink, consultationId], (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/advisor/dashboard?error=reschedule');
      }

      // ✅ Send "rescheduled" notification (no video link yet)
      if (student_email) {
        sendRescheduleNotificationToCustomer(student_email, student_name, new_date)
          .then(() => res.redirect('/advisor/dashboard'))
          .catch(err => {
            console.error('Email send failed:', err);
            res.redirect('/advisor/dashboard?error=email');
          });
      } else {
        res.redirect('/advisor/dashboard');
      }
    });
  });
});

// Mark Consultation as Completed
app.post('/advisor/consultations/:id/complete', (req, res) => {
  const consultationId = req.params.id;

  const sql = `UPDATE consultations SET status = 'completed' WHERE consultation_id = ?`;

  db.query(sql, [consultationId], (err) => {
    if (err) {
      console.error('Error marking consultation as completed:', err);
      return res.status(500).send('Error updating status');
    }
    res.redirect('/advisor/dashboard');
  });
});

// Advisor Notes
// View Notes Page
// Updated: View Clients and Their Consultation History
app.get('/advisor/notes', (req, res) => {
  const advisorId = req.session.user?.user_id;
  if (!advisorId) return res.redirect('/login/advisor');

  const sql = `
    SELECT 
      c.*, 
      u.full_name AS student_name,
      u.email,
      u.date_of_birth,
      u.nric,
      u.user_id AS student_id
    FROM consultations c
    LEFT JOIN users u ON c.customer_id = u.user_id
    WHERE c.advisor_id = ?
    AND c.status = 'completed'
    ORDER BY u.full_name, c.appointment_date DESC
  `;

  db.query(sql, [advisorId], (err, results) => {
    if (err) {
      console.error(err);
      return res.render('advisor-notes', { groupedNotes: {}, error: 'Failed to load notes' });
    }

    // Group consultations by student
    const grouped = {};
    results.forEach(r => {
      if (!grouped[r.student_id]) {
        grouped[r.student_id] = {
          full_name: r.student_name,
          email: r.email,
          date_of_birth: r.date_of_birth,
          nric: r.nric,
          consultations: []
        };
      }
      grouped[r.student_id].consultations.push(r);
    });

    res.render('advisor-notes', { groupedNotes: grouped, error: null });
  });
});


// Update Notes
app.post('/advisor/consultations/:id/notes', (req, res) => {
  const consultationId = req.params.id;
  const { notes } = req.body;

  db.query(
    'UPDATE consultations SET notes = ? WHERE consultation_id = ?',
    [notes, consultationId],
    (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/advisor/notes?error=update');
      }
      res.redirect('/advisor/notes');
    }
  );
});

// Completed Consultations Advisor
app.get('/advisor/completed', (req, res) => {
  const advisorId = req.session.user?.user_id;
  if (!advisorId) return res.redirect('/login/advisor');

  const selected = req.query.period || null;

  const sql = `
    SELECT c.*, u.full_name AS student_name
    FROM consultations c
    LEFT JOIN users u ON u.user_id = c.customer_id
    WHERE c.advisor_id = ? AND c.status = 'completed'
    ORDER BY c.appointment_date DESC
  `;

  db.query(sql, [advisorId], (err, results) => {
    if (err) {
      console.error(err);
      return res.render('advisor-completed', {
        grouped: {},
        periods: [],
        selectedPeriod: null
      });
    }

    const grouped = {};
    const periodsSet = new Set();

    results.forEach(c => {
      const date = new Date(c.appointment_date);
      const key = date.toLocaleString('default', { month: 'long', year: 'numeric' }); // e.g., "July 2025"
      periodsSet.add(key);

      if (!selected || selected === key) {
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push(c);
      }
    });

    const periods = Array.from(periodsSet).sort((a, b) => new Date('1 ' + b) - new Date('1 ' + a));

    res.render('advisor-completed', {
      grouped,
      periods,
      selectedPeriod: selected
    });
  });
});

// Advisor Tools
// Budget Calculator page
app.get('/advisor/tools/budget', (req, res) => {
  if (!req.session.user) return res.redirect('/login/staff');
  res.render('advisor-tools-budget');
});

// Goal Tracker page
app.get('/advisor/tools/goals', (req, res) => {
  if (!req.session.user) return res.redirect('/login/staff');
  res.render('advisor-tools-goals');
});




// Profile
// Advisor Profile
app.get('/advisor/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login/staff');

  const advisorId = req.session.user.user_id;

  const sql = `SELECT * FROM users WHERE user_id = ? AND role = 'financial_advisor'`;

  db.query(sql, [advisorId], (err, results) => {
    if (err || results.length === 0) {
      console.error('Fetch failed:', err);
      return res.status(500).send('Database error or user not found');
    }

    res.render('advisor-profile', {
      advisor: results[0],
      query: req.query
    });
  });
});

app.post('/advisor/profile/update', upload.single('profile_picture'), (req, res) => {
  if (!req.session.user) return res.redirect('/login/staff');

  const advisorId = req.session.user.user_id;
  const { email, phone_number, password } = req.body;
  const profilePicturePath = req.file ? `/images/${req.file.filename}` : null;

  const isPasswordChanged = password && password !== req.session.user.password;

  if (isPasswordChanged) {
    const otpCode = String(Math.floor(100000 + Math.random() * 900000)); // store as string
    const createdAt = new Date();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

    // 🔁 CLEANUP old OTPs
    db.query(`DELETE FROM otp_requests WHERE user_id = ? AND purpose = 'password_reset'`, [advisorId], (cleanupErr) => {
      if (cleanupErr) console.error('❌ OTP cleanup failed:', cleanupErr);

      // 🔐 Insert new OTP
      db.query(
        `INSERT INTO otp_requests (user_id, purpose, otp_code, created_at, expires_at)
         VALUES (?, 'password_reset', ?, ?, ?)`,
        [advisorId, otpCode, createdAt, expiresAt],
        (err) => {
          if (err) {
            console.error('OTP insert failed:', err);
            return res.redirect('/advisor/profile?error=1');
          }

          // 📧 Send OTP Email
          sendAdvisorOtpEmail(req.session.user.email, req.session.user.full_name, otpCode);

          // 💾 Store pending update in session
          req.session.pendingUpdate = {
            email,
            phone_number,
            password,
            profile_picture: profilePicturePath,
          };

          return res.redirect('/advisor/verify-otp');
        }
      );
    });
    return;
  }

  // If password not changed, update profile directly
  let sql = `UPDATE users SET email = ?, phone_number = ?`;
  const params = [email, phone_number];

  if (profilePicturePath) {
    sql += `, profile_picture = ?`;
    params.push(profilePicturePath);
  }

  sql += ` WHERE user_id = ? AND role = 'financial_advisor'`;
  params.push(advisorId);

  db.query(sql, params, (err) => {
    if (err) {
      console.error('Update failed:', err);
      return res.redirect('/advisor/profile?error=1');
    }

    req.session.user.email = email;
    req.session.user.phone_number = phone_number;
    if (profilePicturePath) req.session.user.profile_picture = profilePicturePath;

    res.redirect('/advisor/profile?success=1');
  });
});





// Advisor Change Password OTP
app.get('/advisor/verify-otp', (req, res) => {
  res.render('advisor-verify-otp');
});

app.post('/advisor/verify-otp', (req, res) => {
  const { otp_code } = req.body;
  const advisorId = req.session.user.user_id;
  const now = new Date();

  const otpString = String(otp_code).trim(); // Make sure it's a string!

  console.log('🔎 Verifying OTP:', { advisorId, otpString, now });

  const otpSql = `
    SELECT * FROM otp_requests
    WHERE user_id = ? AND otp_code = ? AND purpose = 'password_reset' AND expires_at > ?
  `;

  db.query(otpSql, [advisorId, otpString, now], (err, results) => {
    if (err) console.error('❌ OTP DB error:', err);
    if (results.length === 0) {
      console.warn('⚠️ No matching OTP');
      return res.render('advisor-verify-otp', { error: 'Invalid or expired OTP.' });
    }

    const update = req.session.pendingUpdate;
    if (!update) return res.redirect('/advisor/profile?error=1');

    let updateSql = `UPDATE users SET email = ?, phone_number = ?, password = ?`;
    const params = [update.email, update.phone_number, update.password];

    if (update.profile_picture) {
      updateSql += `, profile_picture = ?`;
      params.push(update.profile_picture);
    }

    updateSql += ` WHERE user_id = ? AND role = 'financial_advisor'`;
    params.push(advisorId);

    db.query(updateSql, params, (updateErr) => {
      if (updateErr) {
        console.error('Update failed:', updateErr);
        return res.redirect('/advisor/profile?error=1');
      }

      db.query(`DELETE FROM otp_requests WHERE user_id = ? AND purpose = 'password_reset'`, [advisorId]);
      delete req.session.pendingUpdate;

      req.session.user.email = update.email;
      req.session.user.phone_number = update.phone_number;
      req.session.user.password = update.password;
      if (update.profile_picture) req.session.user.profile_picture = update.profile_picture;

      res.redirect('/advisor/profile?success=1');
    });
  });
});



// Customer Consultation Booking Routes

// Customer Consultation History
app.get('/customer/history', async (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const customerId = req.session.user.user_id;
  const { month, year } = req.query;

  // SQL base
  let sql = `
    SELECT c.*, u.full_name AS advisor_name
    FROM consultations c
    LEFT JOIN users u ON c.advisor_id = u.user_id
    WHERE c.customer_id = ? AND c.status = 'completed'
  `;
  const params = [customerId];

  // Filtering logic
  if (month) {
    sql += ` AND MONTH(c.appointment_date) = ?`;
    params.push(month);
  }
  if (year) {
    sql += ` AND YEAR(c.appointment_date) = ?`;
    params.push(year);
  }

  sql += ` ORDER BY c.appointment_date DESC`;

  const [consultations] = await db.promise().query(sql, params);

  // Fetch distinct years (from 2025 onwards)
  const [yearRows] = await db.promise().query(
    `SELECT DISTINCT YEAR(appointment_date) AS year 
     FROM consultations 
     WHERE customer_id = ? AND status = 'completed' AND YEAR(appointment_date) >= 2025
     ORDER BY year DESC`,
    [customerId]
  );

  const years = yearRows.map(r => r.year);

  res.render('customer-history', {
    consultations,
    selectedMonth: month || '',
    selectedYear: year || '',
    years
  });
});








// Customer Consultation Booking
app.get('/customer/consultations', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');

  const userId = req.session.user.user_id;

  const slotSql = `
    SELECT c.*, u.full_name AS advisor_name 
    FROM consultations c 
    LEFT JOIN users u ON c.advisor_id = u.user_id 
    WHERE (c.status = 'available' OR c.customer_id = ?)
    ORDER BY c.appointment_date ASC
  `;

  const completedSql = `
    SELECT COUNT(*) AS count 
    FROM consultations 
    WHERE customer_id = ? AND status = 'completed'
  `;

  db.query(slotSql, [userId], (err, slotResults) => {
    if (err) return res.status(500).send("Database error (slots)");

    const upcomingCount = slotResults.filter(s =>
      s.customer_id === userId &&
      ['booked', 'accepted', 'pending accept'].includes(s.status)
    ).length;

    db.query(completedSql, [userId], (err2, completedResult) => {
      if (err2) return res.status(500).send("Database error (completed)");

      const completedCount = completedResult[0].count;

      res.render('customer-consultation', {
        slots: slotResults,
        user_id: userId,
        upcomingCount,
        completedCount
      });
    });
  });
});




// Book Consultation Slot (Customer Side)
app.post('/customer/book/:id', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');

  const consultationId = req.params.id;
  const customerId = req.session.user.user_id;

  // Check if the slot is still available
  const checkSql = `SELECT * FROM consultations WHERE consultation_id = ? AND status = 'available'`;

  db.query(checkSql, [consultationId], (err, results) => {
    if (err) {
      console.error(err);
      return res.redirect('/customer/consultations?error=db');
    }

    if (results.length === 0) {
      return res.redirect('/customer/consultations?error=unavailable');
    }

    // Update the slot to 'booked' and assign the customer_id
    const updateSql = `
      UPDATE consultations 
      SET customer_id = ?, status = 'booked'
      WHERE consultation_id = ?
    `;

    db.query(updateSql, [customerId, consultationId], (err2) => {
      if (err2) {
        console.error(err2);
        return res.redirect('/customer/consultations?error=updatefail');
      }

      res.redirect('/customer/consultations?booked=1');
    });
  });
});

// Cancel Consultation Slot (Customer Side)
app.post('/customer/cancel/:id', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');

  const consultationId = req.params.id;
  const customerId = req.session.user.user_id;

  const fetchSql = `
    SELECT c.appointment_date, u.full_name AS student_name, a.email AS advisor_email
    FROM consultations c
    LEFT JOIN users u ON c.customer_id = u.user_id
    LEFT JOIN users a ON c.advisor_id = a.user_id
    WHERE c.consultation_id = ? AND c.customer_id = ?
  `;

  db.query(fetchSql, [consultationId, customerId], (err, results) => {
    if (err) {
      console.error(err);
      return res.redirect('/customer/consultations?error=db');
    }

    if (results.length === 0) {
      return res.redirect('/customer/consultations?error=notfound');
    }

    const { advisor_email, student_name, appointment_date } = results[0];

    // Update slot: remove customer and set status back to 'available'
    const updateSql = `
      UPDATE consultations
      SET customer_id = NULL, status = 'available'
      WHERE consultation_id = ?
    `;

    db.query(updateSql, [consultationId], (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/customer/consultations?error=cancel');
      }

      // Send email to advisor if advisor exists
      if (advisor_email) {
        sendCancellationEmailToAdvisor(advisor_email, student_name, appointment_date)
          .then(() => res.redirect('/customer/consultations'))
          .catch(emailErr => {
            console.error('Email failed:', emailErr);
            res.redirect('/customer/consultations?error=email');
          });
      } else {
        res.redirect('/customer/consultations');
      }
    });
  });
});

// Accept Reschedule Request (Customer Side)
app.post('/customer/accept-reschedule/:id', (req, res) => {
  const consultationId = req.params.id;

  const getSql = `
  SELECT 
    c.appointment_date, c.video_link,
    u.email AS student_email, u.full_name AS student_name,
    a.email AS advisor_email, a.full_name AS advisor_name
  FROM consultations c
  LEFT JOIN users u ON c.customer_id = u.user_id
  LEFT JOIN users a ON c.advisor_id = a.user_id
  WHERE c.consultation_id = ?
`;



  db.query(getSql, [consultationId], (err, results) => {
    if (err || results.length === 0) {
      console.error(err || 'No consultation found');
      return res.redirect('/customer/consultations?error=lookup');
    }

    const {
      appointment_date,
      video_link,
      student_email,
      student_name,
      advisor_email,
      advisor_name
    } = results[0];

    const updateSql = `UPDATE consultations SET status = 'accepted' WHERE consultation_id = ?`;

    db.query(updateSql, [consultationId], (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/customer/consultations?error=accept');
      }

      // ✅ Send both emails now
      Promise.all([
        sendRescheduleEmail(student_email, student_name, appointment_date, video_link),
        sendAdvisorVideoLinkEmail(advisor_email, advisor_name, student_name, appointment_date, video_link)
      ])
        .then(() => {
          res.redirect('/customer/consultations');
        })
        .catch((emailErr) => {
          console.error('Email failed:', emailErr);
          res.redirect('/customer/consultations?error=email');
        });
    });
  });
});



//jeli----------------------------------------------------------------
//// View all customer accounts 
app.get('/staff/accounts', (req, res) => {
  const sql = `
    SELECT a.*, u.full_name AS customer_name
    FROM accounts a
    JOIN users u ON a.user_id = u.user_id
    ORDER BY a.account_status DESC, a.created_at DESC
  `;
  db.query(sql, (err, accounts) => {
    if (err) return res.status(500).send("DB error");
    res.render('staff-account-management', { accounts });
  });
});

// Update status
app.post('/staff/account-status', (req, res) => {
  const { account_id, action } = req.body;

  if (action === 'close') {
    const deleteSql = `DELETE FROM accounts WHERE account_id = ?`;
    db.query(deleteSql, [account_id], err => {
      if (err) return res.status(500).send('Failed to close account');
      return res.redirect('/staff/accounts');
    });
  } else if (action === 'suspend' || action === 'activate') {
    const status = action === 'suspend' ? 'suspended' : 'active';
    const updateSql = `UPDATE accounts SET account_status = ? WHERE account_id = ?`;
    db.query(updateSql, [status, account_id], err => {
      if (err) return res.status(500).send('Failed to update status');
      return res.redirect('/staff/accounts');
    });
  } else {
    return res.status(400).send('Invalid action');
  }
});
// POST: Instantly open savings account
app.post('/open-savings', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login/customer');
  }

  const user = req.session.user;
  const checkSql = `SELECT * FROM accounts WHERE user_id = ? AND account_type = 'savings' AND account_status = 'active'`;

  db.query(checkSql, [user.user_id], (err, rows) => {
    if (err) {
      console.error('Check savings account error:', err);
      return res.status(500).send('Server error');
    }
    if (rows.length > 0) {
      return res.send(`<script>alert('You already have a savings account.'); window.location.href='/my-products';</script>`);
    }

    // Proceed to insert since no active savings account exists
    const productId = 3;
    const accountNumber = generateRandomNumber(9);
    const insertSql = `
      INSERT INTO accounts (user_id, product_id, full_name, account_number, account_type, balance, account_status)
      VALUES (?, ?, ?, ?, 'savings', 0.00, 'active')
    `;
    db.query(insertSql, [user.user_id, productId, user.full_name, accountNumber], (err2) => {
      if (err2) {
        console.error('Insert savings account error:', err2);
        return res.status(500).send('Failed to create savings account');
      }
      res.redirect('/dashboard');
    });
  });
});
// POST: Open fixed deposit account
app.post('/open-fixed', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login/customer');
  }

  const user = req.session.user;
  const checkSql = `SELECT * FROM accounts WHERE user_id = ? AND account_type = 'fixed_deposit' AND account_status = 'active'`;

  db.query(checkSql, [user.user_id], (err, rows) => {
    if (err) {
      console.error('Check fixed deposit error:', err);
      return res.status(500).send('Server error');
    }
    if (rows.length > 0) {
      return res.send(`<script>alert('You already have a fixed deposit account.'); window.location.href='/my-products';</script>`);
    }

    const productId = 4;
    const accountNumber = generateRandomNumber(9);
    const insertSql = `
      INSERT INTO accounts (user_id, product_id, full_name, account_number, account_type, balance, account_status)
      VALUES (?, ?, ?, ?, 'fixed_deposit', 0.00, 'active')
    `;
    db.query(insertSql, [user.user_id, productId, user.full_name, accountNumber], (err2) => {
      if (err2) {
        console.error('Insert fixed deposit error:', err2);
        return res.status(500).send('Failed to create fixed deposit account');
      }
      res.redirect('/dashboard');
    });
  });
});


function sendConfirmationEmailStatus(toEmail, fullName, type, status, accountNumber = '') {
  let statusText = status === 'Approved' ? 'approved and created' : status.toLowerCase();
  let accountDetails = accountNumber
    ? `<p>Your account number is: <strong>${accountNumber}</strong>.</p>`
    : '';

  const mailOptions = {
    from: 'TheOfficalHOH@gmail.com',
    to: toEmail,
    subject: `HOH Bank - ${type.replace('_', ' ').toUpperCase()} Application ${status}`,
    html: `
      <h3>Dear ${fullName},</h3>
      <p>We have received your application for ${type.replace('_', ' ')} account. Its current status is <strong>${statusText}</strong>.</p>
      ${accountDetails}
      <p>You will receive another update once it has been reviewed.</p>
      <p>Thank you for choosing HOH Bank.</p>
      <br/>
      <p>Best regards,<br>HOH Bank Team</p>
    `
  };

  return transporter.sendMail(mailOptions);
}




// Replace your existing transporter code with:
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// 💌 Generic email sending function
function sendEmail(to, subject, html) {
  const mailOptions = {
    from: '"HOH Bank" <TheOfficalHOH@gmail.com>',
    to,
    subject,
    html,
  };

  return transporter.sendMail(mailOptions);
}


// Dashboard Analytics Data API (now includes budget goals) -- ben 
// Account Application Pages (Customer)
app.get('/savings-account', (req, res) => {
  res.render('savings-account', { user: req.session.user });
});

app.get('/fixed-account', (req, res) => {
  res.render('fixed-account', { user: req.session.user });
});

// Customer logout route (for customer dashboard)
app.get('/logout/customer', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login/customer');
  });
});

app.get('/dashboard/analytics-data', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const userId = req.session.user.user_id;
  // Parse date range from query (optional)
  let { startDate, endDate, account, category } = req.query;
  let start = startDate ? new Date(startDate) : null;
  let end = endDate ? new Date(endDate) : null;
  if (end) end.setHours(23,59,59,999); // include full end day
  // Get user info (for age)
  db.query('SELECT * FROM users WHERE user_id = ?', [userId], (errUser, users) => {
    if (errUser || users.length === 0) return res.status(500).json({ error: 'DB error (user)' });
    const user = users[0];
    db.query('SELECT * FROM accounts WHERE user_id = ?', [userId], (err, accounts) => {
      if (err) return res.status(500).json({ error: 'DB error (accounts)' });
      const accountIds = accounts.map(a => a.account_id);
      db.query('SELECT * FROM transactions WHERE account_id IN (?)', [accountIds.length ? accountIds : [0]], (err2, transactions) => {
        if (err2) return res.status(500).json({ error: 'DB error (transactions)' });
        // Filter transactions by date range, account, and category if provided
        let filteredTx = transactions;
        if (start || end || account || category) {
          filteredTx = transactions.filter(tx => {
            const txDate = new Date(tx.transaction_date);
            const matchDate = (!start || txDate >= start) && (!end || txDate <= end);
            const matchAccount = !account || tx.account_id == account;
            const matchCategory = !category || (tx.category && tx.category === category) || (tx.transaction_type && tx.transaction_type === category);
            return matchDate && matchAccount && matchCategory;
          });
        }
        db.query('SELECT * FROM budget_goals WHERE user_id = ?', [userId], (err3, goals) => {
          if (err3) return res.status(500).json({ error: 'DB error (budget_goals)' });
          // Calculate daily average balance (last 30 days, unfiltered)
          let dailyAvgBalance = 0;
          if (accounts.length > 0) {
            const now = new Date();
            const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
            let total = 0, days = 0;
            for (let d = 0; d < 30; d++) {
              const day = new Date(thirtyDaysAgo.getTime() + d * 24 * 60 * 60 * 1000);
              let dayTotal = 0;
              accounts.forEach(acc => {
                const txs = transactions.filter(tx => tx.account_id === acc.account_id && new Date(tx.transaction_date) <= day);
                if (txs.length > 0) {
                  const lastTx = txs.reduce((a, b) => new Date(a.transaction_date) > new Date(b.transaction_date) ? a : b);
                  dayTotal += lastTx.balance_after || acc.balance;
                } else {
                  dayTotal += acc.balance;
                }
              });
              total += dayTotal;
              days++;
            }
            dailyAvgBalance = days > 0 ? total / days : 0;
          }
          // Calculate age (if dob exists)
          let age = null;
          if (user.date_of_birth) {
            const dob = new Date(user.date_of_birth);
            const today = new Date();
            age = today.getFullYear() - dob.getFullYear();
            const m = today.getMonth() - dob.getMonth();
            if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
          }
          // --- Analytics: Aggregate Topup and Spending (filtered) ---
          const topupTx = filteredTx.filter(tx => tx.transaction_type === 'topup');
          const spendingTx = filteredTx.filter(tx => tx.transaction_type === 'spending');
          const transferTx = filteredTx.filter(tx => tx.transaction_type === 'transfer');
          // Total sums
          const totalTopup = topupTx.reduce((sum, tx) => sum + parseFloat(tx.amount), 0);
          const totalSpending = spendingTx.reduce((sum, tx) => sum + parseFloat(tx.amount), 0);
          const totalTransfer = transferTx.reduce((sum, tx) => sum + parseFloat(tx.amount), 0);
          // Total balance (sum of all account balances)
          const totalBalance = accounts.reduce((sum, acc) => sum + parseFloat(acc.balance), 0);
          // Recent transactions (last 10, sorted by date desc)
          const recentTransactions = [...filteredTx].sort((a, b) => new Date(b.transaction_date) - new Date(a.transaction_date)).slice(0, 10);
          // Monthly breakdown (last 6 months, filtered)
          const now = new Date();
          const months = [];
          for (let i = 5; i >= 0; i--) {
            const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
            months.push({
              label: d.toLocaleString('default', { month: 'short', year: '2-digit' }),
              year: d.getFullYear(),
              month: d.getMonth() + 1
            });
          }
          const monthlyTopup = months.map(m =>
            topupTx.filter(tx => {
              const dt = new Date(tx.transaction_date);
              return dt.getFullYear() === m.year && dt.getMonth() + 1 === m.month;
            }).reduce((sum, tx) => sum + parseFloat(tx.amount), 0)
          );
          const monthlySpending = months.map(m =>
            spendingTx.filter(tx => {
              const dt = new Date(tx.transaction_date);
              return dt.getFullYear() === m.year && dt.getMonth() + 1 === m.month;
            }).reduce((sum, tx) => sum + parseFloat(tx.amount), 0)
          );
          const monthlyTransfer = months.map(m =>
            transferTx.filter(tx => {
              const dt = new Date(tx.transaction_date);
              return dt.getFullYear() === m.year && dt.getMonth() + 1 === m.month;
            }).reduce((sum, tx) => sum + parseFloat(tx.amount), 0)
          );
          res.json({
            accounts,
            transactions: filteredTx,
            goals,
            age,
            dailyAvgBalance,
            totalTopup,
            totalSpending,
            totalTransfer,
            totalBalance,
            recentTransactions,
            monthlyLabels: months.map(m => m.label),
            monthlyTopup,
            monthlySpending,
            monthlyTransfer
          });
        });
      });
    });
  });
});

// 2FA OTP verification page (GET)
app.get('/verify-otp-2fa', (req, res) => {
  const email = req.query.email;
  res.render('verify-otp', { email, otp2fa: true });
});
// 2FA OTP verification (POST)
app.post('/verify-otp-2fa', (req, res) => {
  require('./controllers/authController').verifyOtp2fa(req, res);
});

// Resend OTP endpoint (for both password reset and 2FA)
app.post('/resend-otp', (req, res) => {
  const { email, purpose } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err || users.length === 0) return res.json({ success: false });
    const user = users[0];
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60000); // 10 min expiry
    // Use provided purpose or default to 'password_reset'
    const otpPurpose = purpose || 'password_reset';
    db.query('INSERT INTO otp_requests (user_id, purpose, otp_code, expires_at) VALUES (?, ?, ?, ?)', [user.user_id, otpPurpose, otp, expiresAt], (err2) => {
      if (err2) return res.json({ success: false });
      // Send OTP email
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        tls: { rejectUnauthorized: false }
      });
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: `HoH Bank ${otpPurpose === 'login_2fa' ? 'Login' : 'Password Reset'} OTP`,
        html: `<h3>Your OTP for ${otpPurpose === 'login_2fa' ? 'login' : 'password reset'} is: <b>${otp}</b></h3><p>This OTP will expire in 10 minutes.</p>`
      };
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) return res.json({ success: false });
        res.json({ success: true });
      });
    });
  });
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login/customer'); // Always redirect to customer login after logout
  });
});

app.get('/analytics', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  res.render('analytics');
});


// Cards page
app.get('/my-cards', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  db.query('SELECT * FROM cards WHERE user_id = ?', [userId], (err, cards) => {
    if (err) {
      console.error('DB error (cards):', err);
      return res.render('customer-cards', { cards: [], searchQuery: '', statusFilter: '' });
    }
    res.render('customer-cards', { cards, searchQuery: '', statusFilter: '' });
  });
});


// Budget Goals page
app.get('/goals', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  db.query('SELECT * FROM budget_goals WHERE user_id = ?', [userId], (err, goals) => {
    if (err) {
      console.error('DB error (budget_goals):', err);
      return res.render('goals', { goals: [], accounts: [] });
    }
    // Calculate savings suggestions for each goal
    const today = new Date();
    const goalsWithSuggestions = goals.map(goal => {
      let dailySuggestion = null;
      let weeklySuggestion = null;
      let daysLeft = null;
      let weeksLeft = null;
      let remaining = Number(goal.goal_amount) - Number(goal.current_savings);
      if (goal.target_date) {
        const target = new Date(goal.target_date);
        daysLeft = Math.ceil((target - today) / (1000 * 60 * 60 * 24));
        weeksLeft = Math.ceil(daysLeft / 7);
        if (daysLeft > 0 && remaining > 0) {
          dailySuggestion = (remaining / daysLeft).toFixed(2);
          weeklySuggestion = (remaining / weeksLeft).toFixed(2);
        }
      }
      return {
        ...goal,
        dailySuggestion,
        weeklySuggestion,
        daysLeft,
        weeksLeft,
        remaining
      };
    });
    db.query('SELECT * FROM accounts WHERE user_id = ?', [userId], (err2, accounts) => {
      if (err2) {
        console.error('DB error (accounts):', err2);
        return res.render('goals', { goals: goalsWithSuggestions, accounts: [] });
      }
      res.render('goals', { goals: goalsWithSuggestions, accounts });
    });
  });
});

// Helper: Send goal completion notifications (email + in-app)
function notifyGoalCompleted(userId, goal) {
  // Get user email
  db.query('SELECT * FROM users WHERE user_id = ?', [userId], (err, users) => {
    if (err || users.length === 0) return;
    const user = users[0];
    // Email
    const subject = 'Congratulations! You completed your savings goal';
    const html = `<h3>Hi ${user.full_name},</h3><p>🎉 You have completed your goal: <b>${goal.goal_name}</b>!</p><p>Target: $${goal.goal_amount}</p><p>Category: ${goal.category}</p><p>Keep up the great saving habits!</p>`;
    sendEmail(user.email, subject, html);
    // In-app notification
    const message = `🎉 You completed your goal: ${goal.goal_name} (Target: $${goal.goal_amount})!`;
    db.query('INSERT INTO user_notifications (user_id, message) VALUES (?, ?)', [userId, message]);
  });
}


// --- Automated Recurring Transfers (node-cron) --- (Ben's section)
const cron = require('node-cron');
cron.schedule('0 2 * * *', () => { // Runs daily at 2am
  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10);
  db.query('SELECT * FROM goal_recurring_transfers WHERE next_transfer_date <= ?', [todayStr], (err, recurs) => {
    if (err) return console.error('Cron DB error (recurring transfers):', err);
    recurs.forEach(rec => {
      // Get account and goal
      db.query('SELECT * FROM accounts WHERE account_id = ?', [rec.account_id], (errA, accs) => {
        if (errA || accs.length === 0) return;
        const account = accs[0];
        if (Number(account.balance) < Number(rec.amount)) return; // skip if insufficient
        db.query('SELECT * FROM budget_goals WHERE goal_id = ?', [rec.goal_id], (errG, goals) => {
          if (errG || goals.length === 0) return;
          const goal = goals[0];
          const newSavings = Number(goal.current_savings) + Number(rec.amount);
          if (newSavings > Number(goal.goal_amount)) return; // skip if would exceed goal
          // Update goal savings
          db.query('UPDATE budget_goals SET current_savings = ? WHERE goal_id = ?', [newSavings, rec.goal_id], (errU) => {
            if (errU) return;
            // Deduct from account
            db.query('UPDATE accounts SET balance = balance - ? WHERE account_id = ?', [rec.amount, rec.account_id], (errD) => {
              if (errD) return;
              // Log transaction
              db.query('INSERT INTO transactions (account_id, transaction_type, amount, description) VALUES (?, "transfer", ?, ?)', [rec.account_id, rec.amount, `Recurring transfer to goal #${rec.goal_id}`], () => {});
              // If completed, notify
              if (newSavings >= Number(goal.goal_amount)) {
                notifyGoalCompleted(goal.user_id, goal);
              }
              // Set next transfer date
              let next = new Date(rec.next_transfer_date);
              if (rec.frequency === 'daily') next.setDate(next.getDate() + 1);
              else if (rec.frequency === 'weekly') next.setDate(next.getDate() + 7);
              else if (rec.frequency === 'monthly') next.setMonth(next.getMonth() + 1);
              const nextStr = next.toISOString().slice(0, 10);
              db.query('UPDATE goal_recurring_transfers SET next_transfer_date = ? WHERE id = ?', [nextStr, rec.id], () => {});
            });
          });
        });
      });
    });
  });
});
// Set up recurring transfer for a goal
app.post('/goals/recurring-transfer/:goalId', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  const goalId = req.params.goalId;
  const { account_id, amount, frequency, start_date } = req.body;
  if (!account_id || !amount || !frequency || !start_date) {
    return res.send('<script>alert("All fields are required."); window.location.href="/goals";</script>');
  }
  db.query('INSERT INTO goal_recurring_transfers (user_id, goal_id, account_id, amount, frequency, next_transfer_date) VALUES (?, ?, ?, ?, ?, ?)',
    [userId, goalId, account_id, amount, frequency, start_date], (err) => {
      if (err) {
        console.error('DB error (recurring transfer):', err);
        return res.send('<script>alert("Failed to set up recurring transfer."); window.location.href="/goals";</script>');
      }
      res.redirect('/goals');
    });
});

// Get goal details and history (for View Details modal)
app.get('/goals/details/:goalId', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const userId = req.session.user.user_id;
  const goalId = req.params.goalId;
  db.query('SELECT * FROM budget_goals WHERE goal_id = ? AND user_id = ?', [goalId, userId], (err, goals) => {
    if (err || goals.length === 0) return res.json({ goal: null });
    const goal = goals[0];
    db.query('SELECT * FROM transactions WHERE description LIKE ? AND account_id IN (SELECT account_id FROM accounts WHERE user_id = ?)', [`%goal #${goalId}%`, userId], (err2, history) => {
      if (err2) return res.json({ goal, history: [] });
      res.json({ goal, history });
    });
  });
});
// Edit Budget Goal
app.post('/goals/edit/:goalId', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  const goalId = req.params.goalId;
  const { goal_name, category, goal_amount, target_date } = req.body;
  // Server-side date validation
  const today = new Date();
  today.setHours(0,0,0,0);
  const selectedDate = new Date(target_date);
  if (!target_date || selectedDate < today) {
    return res.send('<script>alert("Date invalid: Please select a future date."); window.history.back();</script>');
  }
  db.query('UPDATE budget_goals SET goal_name = ?, category = ?, goal_amount = ?, target_date = ? WHERE goal_id = ? AND user_id = ?',
    [goal_name, category, goal_amount, target_date, goalId, userId], (err) => {
      if (err) {
        console.error('DB error (edit goal):', err);
        return res.send('<script>alert("Failed to update goal."); window.location.href="/goals";</script>');
      }
      res.redirect('/goals');
    });
});
// Partial Withdraw from Goal
app.post('/goals/withdraw/:goalId', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  const goalId = req.params.goalId;
  const { withdraw_amount, account_id } = req.body;
  const amount = Number(withdraw_amount);
  if (!amount || amount <= 0) {
    return res.send('<script>alert("Invalid withdrawal amount."); window.location.href="/goals";</script>');
  }
  db.query('SELECT * FROM budget_goals WHERE goal_id = ? AND user_id = ?', [goalId, userId], (err, goals) => {
    if (err || goals.length === 0) {
      return res.send('<script>alert("Goal not found."); window.location.href="/goals";</script>');
    }
    const goal = goals[0];
    if (amount > Number(goal.current_savings)) {
      return res.send('<script>alert("Withdrawal exceeds current savings."); window.location.href="/goals";</script>');
    }
    // Add to account
    db.query('SELECT * FROM accounts WHERE account_id = ? AND user_id = ?', [account_id, userId], (err2, accounts) => {
      if (err2 || accounts.length === 0) {
        return res.send('<script>alert("Account not found."); window.location.href="/goals";</script>');
      }
      // Update goal savings
      const newSavings = Number(goal.current_savings) - amount;
      db.query('UPDATE budget_goals SET current_savings = ? WHERE goal_id = ?', [newSavings, goalId], (err3) => {
        if (err3) {
          return res.send('<script>alert("Failed to update goal savings."); window.location.href="/goals";</script>');
        }
        // Credit to account
        db.query('UPDATE accounts SET balance = balance + ? WHERE account_id = ?', [amount, account_id], (err4) => {
          if (err4) {
            return res.send('<script>alert("Failed to credit account."); window.location.href="/goals";</script>');
          }
          // Log transaction
          db.query('INSERT INTO transactions (account_id, transaction_type, amount, description) VALUES (?, "deposit", ?, ?)', [account_id, amount, `Withdrawal from goal #${goalId}`], () => {
            return res.redirect('/goals');
          });
        });
      });
    });
  });
});

// Add Savings to Goal
app.post('/goals/add-savings/:goalId', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  const goalId = req.params.goalId;
  const { add_amount, account_id } = req.body;
  const addAmount = Number(add_amount);
  if (!addAmount || addAmount <= 0) {
    return res.send('<script>alert("Invalid savings amount."); window.location.href="/goals";</script>');
  }
  // Get goal and account
  db.query('SELECT * FROM budget_goals WHERE goal_id = ? AND user_id = ?', [goalId, userId], (err, goals) => {
    if (err || goals.length === 0) {
      return res.send('<script>alert("Goal not found."); window.location.href="/goals";</script>');
    }
    const goal = goals[0];
    const newSavings = Number(goal.current_savings) + addAmount;
    if (newSavings > Number(goal.goal_amount)) {
      return res.send('<script>alert("Savings cannot exceed goal amount."); window.location.href="/goals";</script>');
    }
    // Deduct from account
    db.query('SELECT * FROM accounts WHERE account_id = ? AND user_id = ?', [account_id, userId], (err2, accounts) => {
      if (err2 || accounts.length === 0) {
        return res.send('<script>alert("Account not found."); window.location.href="/goals";</script>');
      }
      const account = accounts[0];
      if (Number(account.balance) < addAmount) {
        return res.send('<script>alert("Insufficient account balance."); window.location.href="/goals";</script>');
      }
      // Update goal savings
      db.query('UPDATE budget_goals SET current_savings = ? WHERE goal_id = ?', [newSavings, goalId], (err3) => {
        if (err3) {
          return res.send('<script>alert("Failed to update savings."); window.location.href="/goals";</script>');
        }
        // Deduct from account
        db.query('UPDATE accounts SET balance = balance - ? WHERE account_id = ?', [addAmount, account_id], (err4) => {
          if (err4) {
            return res.send('<script>alert("Failed to deduct from account."); window.location.href="/goals";</script>');
          }
          // Log transaction
          db.query('INSERT INTO transactions (account_id, transaction_type, amount, description) VALUES (?, "transfer", ?, ?)', [account_id, addAmount, `Transfer to goal #${goalId}`], (err5) => {
            // If completed, notify
            if (newSavings >= Number(goal.goal_amount)) {
              notifyGoalCompleted(userId, goal);
            }
            // Ignore transaction error for now
            return res.redirect('/goals');
          });
        });
      });
    });
// Route: Get notifications for logged-in user
app.get('/notifications', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const userId = req.session.user.user_id;
  db.query('SELECT * FROM user_notifications WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, notes) => {
    if (err) return res.status(500).json({ error: 'DB error (notifications)' });
    res.json({ notifications: notes });
  });
});
  });
});
// Add Budget Goal
app.post('/goals/add', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  const { goal_name, category, goal_amount, target_date } = req.body;
  // Server-side date validation
  const today = new Date();
  today.setHours(0,0,0,0);
  const selectedDate = new Date(target_date);
  if (!target_date || selectedDate < today) {
    return res.send('<script>alert("Date invalid: Please select a future date."); window.history.back();</script>');
  }
  db.query('INSERT INTO budget_goals (user_id, goal_name, category, goal_amount, current_savings, target_date, created_at) VALUES (?, ?, ?, ?, 0, ?, NOW())',
    [userId, goal_name, category, goal_amount, target_date], (err) => {
      if (err) {
        console.error('DB error (add goal):', err);
        return res.send('<script>alert("Failed to add goal."); window.location.href="/goals";</script>');
      }
      res.redirect('/goals');
    });
});
// Delete Budget Goal
app.post('/goals/delete/:goalId', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  const goalId = req.params.goalId;
  db.query('DELETE FROM budget_goals WHERE goal_id = ? AND user_id = ?', [goalId, userId], (err) => {
    if (err) {
      console.error('DB error (delete goal):', err);
      return res.send('<script>alert("Failed to delete goal."); window.location.href="/goals";</script>');
    }
    res.redirect('/goals');
  });
});
// Edit Budget Goal (GET)
app.get('/goals/edit/:goalId', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  const goalId = req.params.goalId;
  db.query('SELECT * FROM budget_goals WHERE goal_id = ? AND user_id = ?', [goalId, userId], (err, results) => {
    if (err || results.length === 0) {
      return res.send('<script>alert("Goal not found."); window.location.href="/goals";</script>');
    }
    res.render('edit-goal', { goal: results[0] });
  });
});
// Edit Budget Goal (POST)
app.post('/goals/edit/:goalId', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  const goalId = req.params.goalId;
  const { goal_name, category, goal_amount, current_savings, target_date } = req.body;
  db.query('UPDATE budget_goals SET goal_name=?, category=?, goal_amount=?, current_savings=?, target_date=? WHERE goal_id=? AND user_id=?',
    [goal_name, category, goal_amount, current_savings, target_date, goalId, userId], (err) => {
      if (err) {
        console.error('DB error (edit goal):', err);
        return res.send('<script>alert("Failed to update goal."); window.location.href="/goals";</script>');
      }
      res.redirect('/goals');
    });
});

const dialogflowKeyPath = path.join(__dirname, 'hohbankbot-acmq-1fc7d36b67a0.json');
const projectId = 'hohbankbot-acmq';
const sessionClient = new dialogflow.SessionsClient({ keyFilename: dialogflowKeyPath });

app.get('/api/dialogflow', async (req, res) => {
  const question = req.query.question || '';
  const lang = req.query.lang || 'en';
  const sessionId = uuid.v4();
  const sessionPath = sessionClient.sessionPath(projectId, sessionId);

  // --- Authentication for sensitive actions ---
  // Example: If question contains keywords, require login
  const sensitiveKeywords = ['balance', 'account number', 'transaction', 'statement', 'my info', 'my details'];
  const isSensitive = sensitiveKeywords.some(k => question.toLowerCase().includes(k));
  if (isSensitive && !req.session.user) {
    return res.json({ answer: "For your security, please log in to access account-specific information." });
  }

  const request = {
    session: sessionPath,
    queryInput: {
      text: {
        text: question,
        languageCode: lang,
      },
    },
  };

  try {
    const responses = await sessionClient.detectIntent(request);
    const result = responses[0].queryResult;
    console.log('User question:', question);
    console.log('Dialogflow response:', result.fulfillmentText);
    console.log('Matched intent:', result.intent.displayName);

    // --- Escalation: Offer human agent if fallback intent ---
    let escalation = false;
    if (result.intent.isFallback || result.fulfillmentText.toLowerCase().includes("don't know") || result.fulfillmentText.toLowerCase().includes("contact support")) {
      escalation = true;
    }

    res.json({ answer: result.fulfillmentText, escalation });
  } catch (err) {
    console.error('Dialogflow error:', err);
    res.json({ answer: "Sorry, I couldn't connect to Dialogflow.", escalation: false });
  }
});

// --- Chatbot Feedback API ---
app.post('/api/chatbot-feedback', express.json(), (req, res) => {
  const { question, answer, helpful } = req.body;
  // You can log this to a database or file for analytics
  console.log('Chatbot feedback:', { question, answer, helpful, user: req.session.user ? req.session.user.user_id : null });
  res.json({ success: true });
});



// --- Standardized Email OTP for signup (DB-backed, single source of truth) ---
app.post('/send-otp', async (req, res) => {
  let { email } = req.body;
  if (!email) return res.json({ success: false, message: 'Email required.' });
  email = email.trim().toLowerCase();
  // Check if user already exists
  db.query('SELECT user_id FROM users WHERE email = ?', [email], (err, users) => {
    if (err) {
      console.error('DB error:', err);
      return res.json({ success: false, message: 'Database error.' });
    }
    let userId = users.length > 0 ? users[0].user_id : null;
    console.log(`[OTP DEBUG] Lookup user for email: ${email}, found userId: ${userId}`);
    // If not exists, create a temp user for OTP (or you can require registration first)
    if (!userId) {
      db.query('INSERT INTO users (email, email_verified, role) VALUES (?, 0, ?)', [email, 'customer'], (err2, result) => {
        if (err2) {
          console.error('DB insert error:', err2);
          return res.json({ success: false, message: 'Failed to create user for OTP.' });
        }
        userId = result.insertId;
        console.log(`[OTP DEBUG] Created temp user for email: ${email}, new userId: ${userId}`);
        return sendAndStoreOtp(userId, email, res);
      });
    } else {
      return sendAndStoreOtp(userId, email, res);
    }
  });
});

function sendAndStoreOtp(userId, email, res) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 10 * 60000); // 10 min expiry
  console.log(`[OTP DEBUG] Preparing to insert OTP for userId: ${userId}, email: ${email}, otp: ${otp}`);
  db.query('DELETE FROM otp_requests WHERE user_id = ? AND purpose = ?', [userId, 'signup_email_verification'], (delErr) => {
    if (delErr) {
      console.error(`[OTP DEBUG] Error deleting old OTPs for userId: ${userId}:`, delErr);
    }
    db.query('INSERT INTO otp_requests (user_id, purpose, otp_code, expires_at) VALUES (?, ?, ?, ?)',
      [userId, 'signup_email_verification', otp, expiresAt], (otpErr, result) => {
        if (otpErr) {
          console.error(`[OTP DEBUG] OTP DB error for userId: ${userId}, email: ${email}, otp: ${otp}:`, otpErr);
          return res.json({ success: false, message: 'Failed to store OTP.' });
        }
        console.log(`[OTP DEBUG] OTP inserted for userId: ${userId}, otp: ${otp}, insertId: ${result.insertId}`);
        // Send OTP email
        const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
          tls: { rejectUnauthorized: false }
        });
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'HoH Bank Email Verification OTP',
          html: `<h3>Your OTP for email verification is: <b>${otp}</b></h3><p>This OTP will expire in 10 minutes.</p>`
        };
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('[OTP DEBUG] OTP email error:', error);
            return res.json({ success: false, message: 'Failed to send OTP.' });
          }
          console.log(`[OTP DEBUG] OTP email sent to: ${email}, otp: ${otp}`);
          res.json({ success: true });
        });
      });
  });
}


// Standardized verify-otp-signup: check DB for OTP, mark email_verified, send welcome email
app.post('/verify-otp-signup', (req, res) => {
  let { email, otp } = req.body;
  email = email.trim().toLowerCase();
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
    if (err || users.length === 0) {
      return res.json({ success: false, message: 'Invalid email.' });
    }
    const user = users[0];
    db.query('SELECT * FROM otp_requests WHERE user_id = ? AND purpose = ? AND otp_code = ? AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
      [user.user_id, 'signup_email_verification', otp], (err2, otps) => {
        if (!err2 && otps.length > 0) {
          // OTP is valid for signup email verification
          db.query('UPDATE users SET email_verified = 1 WHERE user_id = ?', [user.user_id], (uerr) => {
            if (uerr) {
              return res.json({ success: false, message: 'Failed to verify email.' });
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
              }
              return res.json({ success: true });
            });
          });
        } else {
          return res.json({ success: false, message: 'Invalid or expired OTP.' });
        }
      });
  });
});

// Reset Password
app.get('/reset-password', (req, res) => res.render('reset-password'));
app.post('/reset-password', authController.requestPasswordReset);
app.get('/verify-otp', (req, res) => res.render('verify-otp', { email: req.query.email }));
app.post('/verify-otp', authController.verifyOtp);
app.post('/set-new-password', authController.setNewPassword);



// Change Password (GET)
app.get('/change-password', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  res.render('change-password', { message: null });
});
// Change Password (POST) - Step 1: Request OTP
app.post('/change-password', authController.requestChangePasswordOtp);
// Change Password (POST) - Step 2: Verify OTP and change password
app.post('/verify-otp-change-password', authController.verifyOtpChangePassword);

// Show OTP entry page for change password
app.get('/verify-otp-change-password', (req, res) => {
  if (!req.session.user || !req.session.change_password_pending) return res.redirect('/login/customer');
  res.render('verify-otp-change-password', { email: req.session.user.email, message: null });
});

// Customer Dashboard 
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  const userId = req.session.user.user_id;
  db.query('SELECT * FROM accounts WHERE user_id = ?', [userId], (err, accounts) => {
    if (err) {
      console.error('DB error (accounts):', err);
      const stats = { accounts: 0, total_balance: 0.0, goals: 0, cards: 0 };
      return res.render('customer-dashboard', { accounts: [], cards: [], transactions: [], consultations: [], slots: [], goals: [], user: req.session.user, stats });
    }
    db.query('SELECT * FROM cards WHERE user_id = ?', [userId], (err2, cards) => {
      if (err2) {
        console.error('DB error (cards):', err2);
        const stats = {
          accounts: accounts.length,
          total_balance: Number(accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0)),
          goals: 0,
          cards: 0
        };
        return res.render('customer-dashboard', { accounts, cards: [], transactions: [], consultations: [], slots: [], goals: [], user: req.session.user, stats });
      }
      const accountIds = accounts.map(a => a.account_id);
      if (accountIds.length === 0) {
        const stats = {
          accounts: accounts.length,
          total_balance: Number(accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0)),
          goals: 0,
          cards: cards.length
        };
        return res.render('customer-dashboard', { accounts, cards, transactions: [], consultations: [], slots: [], goals: [], user: req.session.user, stats });
      }
      db.query('SELECT * FROM transactions WHERE account_id IN (?) ORDER BY transaction_date DESC LIMIT 10', [accountIds], (err3, transactions) => {
        if (err3) {
          console.error('DB error (transactions):', err3);
          const stats = {
            accounts: accounts.length,
            total_balance: Number(accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0)),
            goals: 0,
            cards: cards.length
          };
          return res.render('customer-dashboard', { accounts, cards, transactions: [], consultations: [], slots: [], goals: [], user: req.session.user, stats });
        }
        db.query(`SELECT c.*, u.full_name AS advisor_name, u.email AS advisor_email
                  FROM consultations c
                  JOIN users u ON c.advisor_id = u.user_id
                  WHERE c.customer_id = ? AND c.status = 'booked'
                  ORDER BY c.appointment_date DESC`, [userId], (err4, consultations) => {
          if (err4) {
            console.error('DB error (consultations):', err4);
            const stats = {
              accounts: accounts.length,
              total_balance: accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0),
              goals: 0,
              cards: cards.length
            };
            return res.render('customer-dashboard', { accounts, cards, transactions, consultations: [], slots: [], goals: [], user: req.session.user, stats });
          }
          db.query(`SELECT c.consultation_id, c.appointment_date, u.full_name AS advisor_name
                    FROM consultations c
                    JOIN users u ON c.advisor_id = u.user_id
                    WHERE c.status = 'available' AND c.customer_id IS NULL
                    ORDER BY c.appointment_date ASC`, (err5, slots) => {
            if (err5) {
              console.error('DB error (slots for reschedule):', err5);
              const stats = {
                accounts: accounts.length,
                total_balance: Number(accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0)),
                goals: 0,
                cards: cards.length
              };
              return res.render('customer-dashboard', { accounts, cards, transactions, consultations, slots: [], goals: [], user: req.session.user, stats });
            }
            db.query('SELECT * FROM budget_goals WHERE user_id = ?', [userId], (err6, goals) => {
              if (err6) {
                console.error('DB error (budget_goals):', err6);
                const stats = {
                  accounts: accounts.length,
                  total_balance: Number(accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0)),
                  goals: 0,
                  cards: cards.length
                };
                return res.render('customer-dashboard', { accounts, cards, transactions, consultations, slots, goals: [], user: req.session.user, stats });
              }
              const stats = {
                accounts: accounts.length,
                total_balance: Number(accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0)),
                goals: goals.length,
                cards: cards.length
              };
              res.render('customer-dashboard', { accounts, cards, transactions, consultations, slots, goals, user: req.session.user, stats });
            });
          });
        });
      });
    });
  });
});

app.post('/profile/edit', upload.single('profile_picture'), (req, res) => {
  if (!req.session.user) return res.redirect('/login/customer');
  if (!req.body) {
    console.error('req.body is undefined!');
    return res.render('profile-edit', { user: req.session.user, message: 'Profile update failed: No form data received.' });
  }
  // Debug log
  console.log('DEBUG /profile/edit req.body:', req.body);
  const userId = req.session.user.user_id;
  const { email, phone, enable_2fa, full_name, nric, dob } = req.body;
  let profilePicturePath = req.session.user.profile_picture || null;
  if (req.file) {
    profilePicturePath = '/images/' + req.file.filename;
  }
  db.query(
    'UPDATE users SET email = ?, phone_number = ?, enable_2fa = ?, full_name = ?, nric = ?, date_of_birth = ?, profile_picture = ? WHERE user_id = ?',
    [email, phone, enable_2fa ? 1 : 0, full_name, nric, dob, profilePicturePath, userId],
    (err) => {
      if (err) {
        console.error('DB error on profile update:', err);
        return res.render('profile-edit', {
          user: { ...req.session.user, email, phone_number: phone, enable_2fa: enable_2fa ? 1 : 0, full_name, nric, date_of_birth: dob, profile_picture: profilePicturePath },
          message: 'Failed to update profile.'
        });
      }
      // Update session
      req.session.user.email = email;
      req.session.user.phone_number = phone;
      req.session.user.enable_2fa = enable_2fa ? 1 : 0;
      req.session.user.full_name = full_name;
      req.session.user.nric = nric;
      req.session.user.date_of_birth = dob;
      req.session.user.profile_picture = profilePicturePath;
      res.render('profile-edit', { user: req.session.user, message: 'Profile updated successfully.' });
    }
  );
});


// Start server - This should be LAST
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
