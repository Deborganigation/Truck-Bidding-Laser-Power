// ================== DEPENDENCIES ==================
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const xlsx = require('xlsx');
const fs = require('fs');
const sgMail = require('@sendgrid/mail');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

// ================== INITIALIZATION ==================
const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
if (process.env.SENDGRID_API_KEY) {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

// ===== CLOUDINARY CONFIGURATION =====
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// ===== Serve static files (like index.html) =====
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ================== DATABASE POOL ==================
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE, // Make sure this is 'logistics_db' in .env
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 20000,
    dateStrings: true,
    timezone: '+05:30'
};

if (process.env.DB_CA_CERT_CONTENT) {
    dbConfig.ssl = {
        ca: process.env.DB_CA_CERT_CONTENT.replace(/\\n/g, '\n')
    };
    console.log("SSL Configuration loaded from Environment Variable.");
}
const dbPool = mysql.createPool(dbConfig);


// ================== AUTH MIDDLEWARE ==================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'Unauthorized: No token provided' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Forbidden: Invalid token' });
        req.user = user;
        next();
    });
};

const isAdminOrSuperAdmin = (req, res, next) => {
    if (!['Admin', 'Super Admin'].includes(req.user.role)) {
        return res.status(403).json({ success: false, message: 'Forbidden: Admin access required' });
    }
    next();
};

const isSuperAdmin = (req, res, next) => {
    if (req.user.role !== 'Super Admin') {
        return res.status(403).json({ success: false, message: 'Forbidden: Super Admin access required' });
    }
    next();
};

// ================== API ROUTES ==================

// --- NEW APIs FOR MASTER DATA ---
app.get('/api/master-data/truck-types', authenticateToken, async (req, res, next) => {
    try {
        const [truckTypes] = await dbPool.query("SELECT truck_type_id, truck_name, dala_length_feet FROM truck_type_master WHERE is_active = true ORDER BY truck_name");
        res.json({ success: true, data: truckTypes });
    } catch (error) {
        next(error);
    }
});

app.get('/api/master-data/items', authenticateToken, async (req, res, next) => {
    try {
        const [items] = await dbPool.query("SELECT item_id, item_name FROM item_master WHERE is_active = true ORDER BY item_name");
        res.json({ success: true, data: items });
    } catch (error) {
        next(error);
    }
});


// --- 1. AUTH & USER MANAGEMENT ---
app.post('/api/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });
        const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]);
        if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials or account inactive.' });
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        const payload = { userId: user.user_id, role: user.role, fullName: user.full_name, email: user.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });
        delete user.password_hash;
        res.json({ success: true, token, user });
    } catch (error) {
        next(error);
    }
});

app.post('/api/register', async (req, res, next) => {
    try {
        const { FullName, Email, Password, Role, CompanyName, ContactNumber, GSTIN } = req.body;
        const hashedPassword = await bcrypt.hash(Password, 10);
        await dbPool.query('INSERT INTO pending_users (full_name, email, password, role, company_name, contact_number, gstin) VALUES (?, ?, ?, ?, ?, ?, ?)', [FullName, Email, hashedPassword, Role, CompanyName, ContactNumber, GSTIN]);
        res.status(201).json({ success: true, message: 'Registration successful! Awaiting admin approval.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' });
        next(error);
    }
});

// --- 2. SHIPPER (USER) FEATURES ---
app.post('/api/requisitions', authenticateToken, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { items } = req.body;
        if (!items) return res.status(400).json({ success: false, message: 'No load details provided.' });
        
        const parsedItems = JSON.parse(items);
        await connection.beginTransaction();

        const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', ?)", [req.user.userId, new Date()]);
        const reqId = reqResult.insertId;

        for (const load of parsedItems) {
            await connection.query(
                `INSERT INTO truck_loads (requisition_id, created_by, loading_point_address, unloading_point_address, item_id, approx_weight_tonnes, truck_type_id, requirement_date, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending Approval')`,
                [reqId, req.user.userId, load.loading_point_address, load.unloading_point_address, load.item_id, load.approx_weight_tonnes, load.truck_type_id, load.requirement_date]
            );
        }

        await connection.commit();
        res.status(201).json({ success: true, message: 'Load request submitted successfully!' });
    } catch (error) {
        if (connection) await connection.rollback();
        next(error);
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/requisitions/my-status', authenticateToken, async (req, res, next) => {
    try {
        const [myReqs] = await dbPool.query('SELECT * FROM requisitions WHERE created_by = ? ORDER BY requisition_id DESC', [req.user.userId]);
        if (myReqs.length === 0) return res.json({ success: true, data: [] });
        
        const reqIds = myReqs.map(r => r.requisition_id);
        const [loads] = await dbPool.query(`
            SELECT tl.*, ac.awarded_amount, u.full_name as awarded_vendor, im.item_name
            FROM truck_loads tl
            LEFT JOIN awarded_contracts ac ON tl.load_id = ac.load_id
            LEFT JOIN users u ON ac.vendor_id = u.user_id
            JOIN item_master im ON tl.item_id = im.item_id
            WHERE tl.requisition_id IN (?) ORDER BY tl.load_id ASC
        `, [reqIds]);
        
        const finalData = myReqs.map(req => ({ ...req, loads: loads.filter(load => load.requisition_id === req.requisition_id) }));
        res.json({ success: true, data: finalData });
    } catch (error) {
        next(error);
    }
});

// --- 3. TRUCKER (VENDOR) FEATURES ---
app.get('/api/requirements/assigned', authenticateToken, async (req, res, next) => {
    try {
        const vendorId = req.user.userId;
        const query = `
            SELECT 
                tl.load_id, tl.requisition_id, tl.loading_point_address, tl.unloading_point_address, tl.approx_weight_tonnes, tl.requirement_date, 
                im.item_name, ttm.truck_name, ttm.dala_length_feet,
                (SELECT COUNT(*) FROM bidding_history_log WHERE load_id = tl.load_id AND vendor_id = ?) as bid_attempts,
                (SELECT JSON_ARRAYAGG(JSON_OBJECT('bid_amount', bhl.bid_amount, 'rank', (SELECT COUNT(DISTINCT b_rank.vendor_id) + 1 FROM bids b_rank WHERE b_rank.load_id = bhl.load_id AND b_rank.bid_amount < bhl.bid_amount))) FROM bidding_history_log bhl WHERE bhl.load_id = tl.load_id AND bhl.vendor_id = ? ORDER BY bhl.submitted_at ASC) AS my_bid_history,
                CASE WHEN b.bid_id IS NOT NULL THEN (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.load_id = tl.load_id AND b2.bid_amount < b.bid_amount) ELSE NULL END AS my_rank
            FROM truck_loads tl
            JOIN trucker_assignments ta ON tl.requisition_id = ta.requisition_id
            JOIN item_master im ON tl.item_id = im.item_id
            JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id
            LEFT JOIN bids b ON tl.load_id = b.load_id AND b.vendor_id = ?
            WHERE ta.vendor_id = ? AND tl.status = 'Active'
            ORDER BY tl.requirement_date ASC, tl.load_id DESC`;
        const [loads] = await dbPool.query(query, [vendorId, vendorId, vendorId, vendorId]);
        res.json({ success: true, data: loads });
    } catch (error) {
        next(error);
    }
});

app.post('/api/bids/bulk', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'Vendor') return res.status(403).json({ success: false, message: 'Forbidden' });
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { bids } = req.body;
        if (!bids || bids.length === 0) return res.status(400).json({ success: false, message: 'No bids to submit.' });
        
        await connection.beginTransaction();
        let submittedCount = 0;
        for (const bid of bids) {
            const { itemId: load_id, bid_amount, comments } = bid;
            const vendorId = req.user.userId;
            const [[countResult]] = await connection.query('SELECT COUNT(*) as count FROM bidding_history_log WHERE load_id = ? AND vendor_id = ?', [load_id, vendorId]);
            if (countResult.count < 3) {
                await connection.query('DELETE FROM bids WHERE load_id = ? AND vendor_id = ?', [load_id, vendorId]);
                const [result] = await connection.query("INSERT INTO bids (load_id, vendor_id, bid_amount, comments, submitted_at) VALUES (?, ?, ?, ?, ?)", [load_id, vendorId, bid_amount, comments, new Date()]);
                await connection.query("INSERT INTO bidding_history_log (bid_id, load_id, vendor_id, bid_amount, submitted_at) VALUES (?, ?, ?, ?, ?)", [result.insertId, load_id, vendorId, bid_amount, new Date()]);
                submittedCount++;
            }
        }
        await connection.commit();
        res.json({ success: true, message: `${submittedCount} bid(s) submitted successfully.` });
    } catch (error) {
        if (connection) await connection.rollback();
        next(error);
    } finally {
        if (connection) connection.release();
    }
});

// --- 4. ADMIN FEATURES ---
app.get('/api/requirements/pending', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => {
    try {
        const [groupedReqs] = await dbPool.query(`SELECT r.requisition_id, r.created_at, u.full_name as creator FROM requisitions r JOIN users u ON r.created_by = u.user_id WHERE r.status = 'Pending Approval' ORDER BY r.requisition_id DESC`);
        const [pendingLoads] = await dbPool.query(`SELECT tl.*, im.item_name, ttm.truck_name FROM truck_loads tl JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id WHERE tl.status = 'Pending Approval'`);
        const [allTruckers] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1");
        res.json({ success: true, data: { groupedReqs, pendingLoads, allTruckers } });
    } catch (error) {
        next(error);
    }
});

app.post('/api/requisitions/approve', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { approvedItemIds: approvedLoadIds, vendorAssignments: truckerAssignments, requisitionId } = req.body;
        
        await connection.beginTransaction();

        if (approvedLoadIds && approvedLoadIds.length > 0) {
            await connection.query("UPDATE truck_loads SET status = 'Active' WHERE load_id IN (?)", [approvedLoadIds]);
        }
        await connection.query("UPDATE requisitions SET status = 'Processed', approved_at = ? WHERE requisition_id = ?", [new Date(), requisitionId]);
        
        if (truckerAssignments) {
            await connection.query('DELETE FROM trucker_assignments WHERE requisition_id = ?', [requisitionId]);
            if (truckerAssignments.length > 0) {
                const values = truckerAssignments.map(vId => [requisitionId, vId, new Date()]);
                await connection.query('INSERT INTO trucker_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]);
            }
        }
        await connection.commit();
        res.json({ success: true, message: 'Load requests processed!' });
    } catch (error) {
        if (connection) await connection.rollback();
        next(error);
    } finally {
        if (connection) connection.release();
    }
});

// --- USER MANAGEMENT & OTHER ROUTES (Mostly unchanged from your original) ---
// (Paste the remaining routes from your old index.js here, after this comment)
// ... for example: app.get('/api/admin/bidding-history', ...), app.get('/api/users', ...), etc.
// IMPORTANT: You will need to manually update any routes that used 'requisition_items' or 'item_id'
// For example, in /api/admin/bidding-history, you need to join with `truck_loads` on `load_id`.

// ================== GLOBAL ERROR HANDLER ==================
app.use((err, req, res, next) => {
    console.error("====== GLOBAL ERROR HANDLER CAUGHT AN ERROR ======");
    console.error("ROUTE: ", req.method, req.originalUrl);
    console.error(err);
    res.status(500).send({ success: false, message: err.message || 'Something went wrong!' });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server is running on http://localhost:${PORT}`));
