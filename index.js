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
    database: 'logistics_db', // <-- IMPORTANT: Using the new database name
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
} else {
    console.warn("WARNING: DB_CA_CERT_CONTENT is not set. SSL connection might fail in production.");
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

// --- 1. AUTH & USER MANAGEMENT (No changes here, kept as is) ---
app.post('/api/login', async (req, res, next) => { try { const { email, password } = req.body; if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' }); const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]); if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials or account inactive.' }); const user = rows[0]; if (!user.password_hash) return res.status(500).json({ success: false, message: 'Server configuration error.' }); const match = await bcrypt.compare(password, user.password_hash); if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' }); const payload = { userId: user.user_id, role: user.role, fullName: user.full_name, email: user.email }; const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' }); const forceReset = !!user.force_password_reset; delete user.password_hash; res.json({ success: true, token, user, forceReset }); } catch (error) { next(error); }});
app.post('/api/register', async (req, res, next) => { try { const { FullName, Email, Password, Role, CompanyName, ContactNumber, GSTIN } = req.body; const hashedPassword = await bcrypt.hash(Password, 10); await dbPool.query('INSERT INTO pending_users (full_name, email, password, role, company_name, contact_number, gstin, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [FullName, Email, hashedPassword, Role, CompanyName, ContactNumber, GSTIN, new Date()]); res.status(201).json({ success: true, message: 'Registration successful! Awaiting admin approval.' }); } catch (error) { if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' }); next(error); }});


// --- 2. SHIPPER (USER) FEATURES ---

// UPDATED: Create new Truck Load Request
app.post('/api/requisitions', authenticateToken, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { items } = req.body; // The frontend sends an 'items' array

        if (!items || items.length === 0) {
            return res.status(400).json({ success: false, message: 'No load details provided.' });
        }
        
        const parsedItems = JSON.parse(items);
        await connection.beginTransaction();

        const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', ?)", [req.user.userId, new Date()]);
        const reqId = reqResult.insertId;

        for (const [i, load] of parsedItems.entries()) {
            if (!load.loading_point_address || !load.unloading_point_address || !load.item_id || !load.approx_weight_tonnes || !load.truck_type_id || !load.requirement_date) {
                throw new Error('Missing required fields for the truck load.');
            }
            const sql = `INSERT INTO truck_loads (requisition_id, created_by, loading_point_address, unloading_point_address, item_id, approx_weight_tonnes, truck_type_id, requirement_date, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending Approval', ?)`;
            const params = [reqId, req.user.userId, load.loading_point_address, load.unloading_point_address, load.item_id, load.approx_weight_tonnes, load.truck_type_id, load.requirement_date, new Date()];
            await connection.query(sql, params);
        }

        await connection.commit();
        res.status(201).json({ success: true, message: 'Truck load request submitted successfully!' });
    } catch (error) {
        if (connection) await connection.rollback();
        next(error);
    } finally {
        if (connection) connection.release();
    }
});

// UPDATED: Shipper's view of their own load statuses
app.get('/api/requisitions/my-status', authenticateToken, async (req, res, next) => {
    try {
        const [myReqs] = await dbPool.query('SELECT * FROM requisitions WHERE created_by = ? ORDER BY requisition_id DESC', [req.user.userId]);
        if (myReqs.length === 0) return res.json({ success: true, data: [] });
        
        const reqIds = myReqs.map(r => r.requisition_id);
        
        const [loads] = await dbPool.query(`
            SELECT 
                tl.*, 
                ac.awarded_amount,
                u.full_name as awarded_vendor,
                im.item_name,
                ttm.truck_name
            FROM truck_loads tl
            LEFT JOIN awarded_contracts ac ON tl.load_id = ac.load_id
            LEFT JOIN users u ON ac.vendor_id = u.user_id
            LEFT JOIN item_master im ON tl.item_id = im.item_id
            LEFT JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id
            WHERE tl.requisition_id IN (?) ORDER BY tl.load_id ASC
        `, [reqIds]);
        
        const finalData = myReqs.map(req => ({ ...req, loads: loads.filter(load => load.requisition_id === req.requisition_id) }));
        res.json({ success: true, data: finalData });
    } catch (error) {
        next(error);
    }
});

// --- 3. TRUCKER (VENDOR) FEATURES ---

// UPDATED: Trucker's view of assigned loads
app.get('/api/requirements/assigned', authenticateToken, async (req, res, next) => {
    try {
        const vendorId = req.user.userId;
        const query = `
            SELECT 
                tl.load_id, tl.requisition_id, tl.loading_point_address, tl.unloading_point_address,
                tl.approx_weight_tonnes, tl.requirement_date, im.item_name, ttm.truck_name, ttm.dala_length_feet,
                (SELECT COUNT(*) FROM bidding_history_log WHERE load_id = tl.load_id AND vendor_id = ?) as bid_attempts,
                (SELECT JSON_ARRAYAGG(JSON_OBJECT('bid_amount', bhl.bid_amount, 'rank', (SELECT COUNT(DISTINCT b_rank.vendor_id) + 1 FROM bids b_rank WHERE b_rank.load_id = bhl.load_id AND b_rank.bid_amount < bhl.bid_amount))) FROM bidding_history_log bhl WHERE bhl.load_id = tl.load_id AND bhl.vendor_id = ? ORDER BY bhl.submitted_at ASC) AS my_bid_history,
                CASE WHEN b.bid_id IS NOT NULL THEN (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.load_id = tl.load_id AND b2.bid_amount < b.bid_amount) ELSE NULL END AS my_rank
            FROM truck_loads tl
            JOIN trucker_assignments ta ON tl.requisition_id = ta.requisition_id
            JOIN item_master im ON tl.item_id = im.item_id
            JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id
            LEFT JOIN bids b ON tl.load_id = b.load_id AND b.vendor_id = ?
            WHERE ta.vendor_id = ? AND tl.status = 'Active'
            ORDER BY tl.requirement_date ASC, tl.load_id DESC;
        `;
        const [loads] = await dbPool.query(query, [vendorId, vendorId, vendorId, vendorId]);
        res.json({ success: true, data: loads });
    } catch (error) {
        next(error);
    }
});

// UPDATED: Logic for submitting bids
app.post('/api/bids/bulk', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'Vendor') return res.status(403).json({ success: false, message: 'Forbidden' });
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { bids } = req.body;
        if (!bids || bids.length === 0) return res.status(400).json({ success: false, message: 'No bids to submit.' });
        
        await connection.beginTransaction();
        let submittedCount = 0;
        const skippedBids = [];

        for (const bid of bids) {
            // Note: Frontend will need to send load_id as itemId
            const { itemId: load_id, bid_amount, comments } = bid;
            const vendorId = req.user.userId;

            try {
                const [[countResult]] = await connection.query('SELECT COUNT(*) as count FROM bidding_history_log WHERE load_id = ? AND vendor_id = ?', [load_id, vendorId]);
                if (countResult.count >= 3) {
                    skippedBids.push(`Load ID ${load_id} (Limit Reached)`);
                    continue;
                }

                await connection.query('DELETE FROM bids WHERE load_id = ? AND vendor_id = ?', [load_id, vendorId]);
                const [result] = await connection.query("INSERT INTO bids (load_id, vendor_id, bid_amount, comments, bid_status, submitted_at) VALUES (?, ?, ?, ?, 'Submitted', ?)", [load_id, vendorId, bid_amount, comments, new Date()]);
                await connection.query("INSERT INTO bidding_history_log (bid_id, load_id, vendor_id, bid_amount, bid_status, submitted_at) VALUES (?, ?, ?, ?, 'Submitted', ?)", [result.insertId, load_id, vendorId, bid_amount, new Date()]);
                submittedCount++;
            } catch (itemError) {
                console.error(`Error processing bid for load ID ${load_id}:`, itemError);
                skippedBids.push(`Load ID ${load_id} (Processing Error)`);
            }
        }
        await connection.commit();
        let message = `${submittedCount} bid(s) submitted successfully.`;
        if (skippedBids.length > 0) {
            message += ` The following loads were skipped: ${skippedBids.join(', ')}.`;
        }
        res.json({ success: true, message });
    } catch (error) {
        if (connection) await connection.rollback();
        next(error);
    } finally {
        if (connection) connection.release();
    }
});


// --- 4. ADMIN & SUPER ADMIN FEATURES ---

// UPDATED: Admin's view of pending requisitions/loads
app.get('/api/requirements/pending', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => {
    try {
        const query = `SELECT r.requisition_id, r.created_at, u.full_name as creator FROM requisitions r LEFT JOIN users u ON r.created_by = u.user_id WHERE r.status = 'Pending Approval' ORDER BY r.requisition_id DESC`;
        const [groupedReqs] = await dbPool.query(query);

        const [pendingLoads] = await dbPool.query(`SELECT tl.*, im.item_name, ttm.truck_name FROM truck_loads tl JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id WHERE tl.status = 'Pending Approval'`);
        
        const [allTruckers] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1");

        res.json({ success: true, data: { groupedReqs, pendingLoads, allTruckers } });
    } catch (error) {
        next(error);
    }
});

// UPDATED: Admin's logic to approve loads and assign truckers
app.post('/api/requisitions/approve', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        // Frontend will send approved load_ids as approvedItemIds
        const { approvedItemIds: approvedLoadIds, vendorAssignments, requisitionId } = req.body;
        
        await connection.beginTransaction();

        if (approvedLoadIds && approvedLoadIds.length > 0) {
            await connection.query("UPDATE truck_loads SET status = 'Active' WHERE load_id IN (?)", [approvedLoadIds]);
        }

        await connection.query("UPDATE requisitions SET status = 'Processed', approved_at = ? WHERE requisition_id = ?", [new Date(), requisitionId]);
        
        if (vendorAssignments) {
            await connection.query('DELETE FROM trucker_assignments WHERE requisition_id = ?', [requisitionId]);
            if (vendorAssignments.length > 0) {
                const values = vendorAssignments.map(vId => [requisitionId, vId, new Date()]);
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

// UPDATED: Admin's view of all active loads
app.get('/api/requirements/active', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => {
    try {
        const query = `
            SELECT 
                tl.*, 
                im.item_name,
                ttm.truck_name,
                l1_details.l1_rate,
                l1_details.l1_vendor,
                (SELECT GROUP_CONCAT(u_assign.full_name SEPARATOR ', ') 
                 FROM trucker_assignments ta 
                 JOIN users u_assign ON ta.vendor_id = u_assign.user_id 
                 WHERE ta.requisition_id = tl.requisition_id) as assigned_truckers
            FROM truck_loads tl
            JOIN item_master im ON tl.item_id = im.item_id
            JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id
            LEFT JOIN (
                SELECT 
                    b.load_id, 
                    MIN(b.bid_amount) as l1_rate,
                    (SELECT u.full_name FROM bids b_inner JOIN users u ON b_inner.vendor_id = u.user_id WHERE b_inner.load_id = b.load_id ORDER BY b_inner.bid_amount ASC LIMIT 1) as l1_vendor
                FROM bids b GROUP BY b.load_id
            ) AS l1_details ON tl.load_id = l1_details.load_id
            WHERE tl.status IN ('Active', 'Bidding Closed')
            ORDER BY tl.requisition_id DESC, tl.load_id ASC
        `;
        const [loads] = await dbPool.query(query);
        res.json({ success: true, data: loads });
    } catch (error) {
        next(error);
    }
});

// UPDATED: Admin's view of bids for a specific load
app.get('/api/items/:id/bids', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => {
    try {
        const loadId = req.params.id;
        const [bids] = await dbPool.query(`SELECT b.*, u.full_name as vendor_name, u.email as vendor_email FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.load_id = ? ORDER BY b.bid_amount ASC`, [loadId]);
        const [[loadDetails]] = await dbPool.query('SELECT * FROM truck_loads WHERE load_id = ?', [loadId]);
        res.json({ success: true, data: { bids, itemDetails: loadDetails } }); // kept itemDetails name for frontend compatibility
    } catch (error) {
        next(error);
    }
});

// UPDATED: Awarding contracts
app.post('/api/contracts/award', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => {
    const { bids } = req.body;
    let connection;
    try {
        connection = await dbPool.getConnection();
        await connection.beginTransaction();

        for (const bid of bids) {
            const loadId = bid.item_id; // Frontend sends load_id as item_id
            const [[loadDetails]] = await connection.query('SELECT * FROM truck_loads WHERE load_id = ?', [loadId]);
            if (!loadDetails) throw new Error(`Load with ID ${loadId} not found.`);

            await connection.query("UPDATE truck_loads SET status = 'Awarded' WHERE load_id = ?", [loadId]);
            await connection.query("UPDATE bids SET bid_status = 'Awarded' WHERE bid_id = ?", [bid.bid_id]);
            await connection.query("UPDATE bids SET bid_status = 'Rejected' WHERE load_id = ? AND bid_id != ?", [loadId, bid.bid_id]);
            await connection.query('DELETE FROM awarded_contracts WHERE load_id = ?', [loadId]);
            
            const insertQuery = `INSERT INTO awarded_contracts (load_id, requisition_id, vendor_id, vendor_name, awarded_amount, winning_bid_id, remarks, awarded_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
            await connection.query(insertQuery, [loadId, loadDetails.requisition_id, bid.vendor_id, bid.vendor_name, bid.bid_amount, bid.bid_id, bid.remarks, new Date()]);
        }

        await connection.commit();
        res.json({ success: true, message: 'Contracts awarded successfully!' });
    } catch (error) {
        if (connection) await connection.rollback();
        next(error);
    } finally {
        if (connection) connection.release();
    }
});


// =================================================================================================
// NOTE: Other endpoints like user management, messaging, reports etc. are not changed for now
// as they primarily interact with the `users` and `messages` tables which are unchanged.
// They can be refined later if needed. The core bidding logic is now updated.
// =================================================================================================


// --- USER MANAGEMENT & UTILITIES (Unchanged) ---
app.get('/api/users/pending', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => { try { const [rows] = await dbPool.query(`SELECT * FROM pending_users ORDER BY temp_id DESC`); res.json({ success: true, data: rows }); } catch (error) { next(error); }});
app.post('/api/users/approve', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => { try { const { temp_id } = req.body; const [[pendingUser]] = await dbPool.query('SELECT * FROM pending_users WHERE temp_id = ?', [temp_id]); if (!pendingUser) return res.status(404).json({ success: false, message: 'User not found' }); await dbPool.query('INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin) VALUES (?, ?, ?, ?, ?, ?, ?)', [pendingUser.full_name, pendingUser.email, pendingUser.password, pendingUser.role, pendingUser.company_name, pendingUser.contact_number, pendingUser.gstin]); await dbPool.query('DELETE FROM pending_users WHERE temp_id = ?', [temp_id]); res.json({ success: true, message: 'User approved!' }); } catch (error) { next(error); }});
app.get('/api/users', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => { try { const allowedSortColumns = ['full_name', 'role']; const sortBy = allowedSortColumns.includes(req.query.sortBy) ? req.query.sortBy : 'full_name'; const order = req.query.order === 'desc' ? 'DESC' : 'ASC'; const query = ` SELECT user_id, full_name, email, role, company_name, contact_number, gstin, is_active FROM users ORDER BY ${sortBy} ${order} `; const [rows] = await dbPool.query(query); res.json({ success: true, data: rows }); } catch (error) { next(error); }});
app.get('/api/users/vendors', authenticateToken, async (req, res, next) => { try { const [vendors] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1"); res.json({ success: true, data: vendors }); } catch (error) { next(error); }});
app.put('/api/users/:id', authenticateToken, isAdminOrSuperAdmin, async (req, res, next) => { try { const { id } = req.params; const { full_name, email, role, company_name, contact_number, gstin, password } = req.body; if (role === 'Super Admin' && req.user.role !== 'Super Admin') { return res.status(403).json({ success: false, message: "Forbidden: Only a Super Admin can assign the Super Admin role." }); } let query = 'UPDATE users SET full_name=?, email=?, role=?, company_name=?, contact_number=?, gstin=?'; let params = [full_name, email, role, company_name, contact_number, gstin]; if (password) { const hashedPassword = await bcrypt.hash(password, 10); query += ', password_hash=?, force_password_reset=?'; params.push(hashedPassword, true); } query += ' WHERE user_id=?'; params.push(id); await dbPool.query(query, params); res.json({ success: true, message: 'User updated successfully.' }); } catch (error) { next(error); }});
app.post('/api/users/set-password', authenticateToken, async (req, res, next) => { try { const { newPassword } = req.body; if (!newPassword || newPassword.length < 4) { return res.status(400).json({ success: false, message: 'Password is too short.' }); } const hashedPassword = await bcrypt.hash(newPassword, 10); await dbPool.query( 'UPDATE users SET password_hash = ?, force_password_reset = ? WHERE user_id = ?', [hashedPassword, false, req.user.userId] ); res.json({ success: true, message: 'Password updated successfully.' }); } catch(error) { next(error); }});


// --- MESSAGING API (Unchanged) ---
app.post('/api/messages', authenticateToken, async (req, res, next) => { try { const { recipientId, messageBody } = req.body; const indianTimestamp = new Date(); await dbPool.query('INSERT INTO messages (sender_id, recipient_id, message_body, timestamp) VALUES (?, ?, ?, ?)', [req.user.userId, recipientId, messageBody, indianTimestamp]); res.status(201).json({ success: true, message: 'Message sent' }); } catch (error) { next(error); }});
app.get('/api/conversations/list', authenticateToken, async (req, res, next) => { try { const myId = req.user.userId; let chattableUsersQuery; if (req.user.role === 'Vendor') { chattableUsersQuery = "SELECT user_id, full_name, role FROM users WHERE role IN ('Admin', 'User', 'Super Admin') AND is_active = 1"; } else { chattableUsersQuery = "SELECT user_id, full_name, role FROM users WHERE user_id != ? AND is_active = 1"; } const [users] = await dbPool.query(chattableUsersQuery, [myId]); if (users.length === 0) return res.json({ success: true, data: [] }); const userMap = new Map(users.map(u => [u.user_id, { ...u, lastMessage: null, lastMessageTimestamp: null, unreadCount: 0 }])); const otherUserIds = Array.from(userMap.keys()); if (otherUserIds.length > 0) { const lastMessagesQuery = ` SELECT CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END as other_user_id, message_body, timestamp FROM messages WHERE message_id IN ( SELECT MAX(message_id) FROM messages WHERE (sender_id = ? AND recipient_id IN (?)) OR (recipient_id = ? AND sender_id IN (?)) GROUP BY LEAST(sender_id, recipient_id), GREATEST(sender_id, recipient_id) )`; const [lastMessages] = await dbPool.query(lastMessagesQuery, [myId, myId, otherUserIds, myId, otherUserIds]); const unreadQuery = `SELECT sender_id, COUNT(*) as count FROM messages WHERE recipient_id = ? AND is_read = 0 GROUP BY sender_id`; const [unreadCounts] = await dbPool.query(unreadQuery, [myId]); lastMessages.forEach(msg => { if (userMap.has(msg.other_user_id)) { const user = userMap.get(msg.other_user_id); user.lastMessage = msg.message_body; user.lastMessageTimestamp = msg.timestamp; }}); unreadCounts.forEach(uc => { if (userMap.has(uc.sender_id)) { userMap.get(uc.sender_id).unreadCount = uc.count; }}); } const sortedUsers = Array.from(userMap.values()).sort((a, b) => (new Date(b.lastMessageTimestamp) || 0) - (new Date(a.lastMessageTimestamp) || 0)); res.json({ success: true, data: sortedUsers }); } catch (error) { next(error); }});
app.get('/api/messages/:otherUserId', authenticateToken, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { otherUserId } = req.params; const myId = req.user.userId; await connection.beginTransaction(); const [messages] = await connection.query(`SELECT *, IF(is_read, 'read', 'sent') as status FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) ORDER BY timestamp ASC`, [myId, otherUserId, otherUserId, myId]); await connection.query(`UPDATE messages SET is_read = 1 WHERE recipient_id = ? AND sender_id = ? AND is_read = 0`, [myId, otherUserId]); await connection.commit(); res.json({ success: true, data: messages }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});


// ================== GLOBAL ERROR HANDLER ==================
app.use((err, req, res, next) => {
    console.error("====== GLOBAL ERROR HANDLER CAUGHT AN ERROR ======");
    console.error("ROUTE: ", req.method, req.originalUrl, err.message);
    res.status(500).send({ success: false, message: err.message || 'Something went wrong!', error: process.env.NODE_ENV === 'development' ? err.stack : undefined });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server is running on http://localhost:${PORT}`));
