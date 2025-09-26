// ================== DEPENDENCIES ==================
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const path = require('path');

// ================== INITIALIZATION ==================
const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Serve static files (like index.html)
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ================== DATABASE POOL ==================
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE || 'logistics_db', // Ensure DB is set in .env
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

// ================== MIDDLEWARE ==================
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

const isAdmin = (req, res, next) => {
    if (!['Admin', 'Super Admin'].includes(req.user.role)) {
        return res.status(403).json({ success: false, message: 'Forbidden: Admin access required' });
    }
    next();
};

// ================== API ROUTES ==================

// --- 1. MASTER DATA APIs ---
app.get('/api/master-data/truck-types', authenticateToken, async (req, res, next) => {
    try {
        const [truckTypes] = await dbPool.query("SELECT truck_type_id, truck_name FROM truck_type_master WHERE is_active = true ORDER BY truck_name");
        res.json({ success: true, data: truckTypes });
    } catch (error) { next(error); }
});

app.get('/api/master-data/items', authenticateToken, async (req, res, next) => {
    try {
        const [items] = await dbPool.query("SELECT item_id, item_name FROM item_master WHERE is_active = true ORDER BY item_name");
        res.json({ success: true, data: items });
    } catch (error) { next(error); }
});

// --- 2. AUTH & REGISTRATION ---
app.post('/api/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]);
        if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials or account inactive.' });
        
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        
        const payload = { userId: user.user_id, role: user.role, fullName: user.full_name, email: user.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });
        
        delete user.password_hash;
        res.json({ success: true, token, user });
    } catch (error) { next(error); }
});

app.post('/api/register', async (req, res, next) => {
    try {
        const { FullName, Email, Password, Role, CompanyName, ContactNumber, GSTIN } = req.body;
        const hashedPassword = await bcrypt.hash(Password, 10);
        // Corrected Role mapping from frontend to DB
        const dbRole = (Role === 'Trucker') ? 'Vendor' : 'User';
        await dbPool.query('INSERT INTO pending_users (full_name, email, password, role, company_name, contact_number, gstin) VALUES (?, ?, ?, ?, ?, ?, ?)', [FullName, Email, hashedPassword, dbRole, CompanyName, ContactNumber, GSTIN]);
        res.status(201).json({ success: true, message: 'Registration successful! Awaiting admin approval.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' });
        next(error);
    }
});

// --- 3. SHIPPER APIs ---
app.post('/api/loads', authenticateToken, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { items } = req.body; // Expects a JSON string of an array of loads
        if (!items) return res.status(400).json({ success: false, message: 'No load details provided.' });
        
        await connection.beginTransaction();
        const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', ?)", [req.user.userId, new Date()]);
        const reqId = reqResult.insertId;

        const parsedLoads = JSON.parse(items);
        for (const load of parsedLoads) {
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
            WHERE tl.requisition_id IN (?) ORDER BY tl.load_id ASC`, [reqIds]);
        
        const finalData = myReqs.map(req => ({ ...req, loads: loads.filter(load => load.requisition_id === req.requisition_id) }));
        res.json({ success: true, data: finalData });
    } catch (error) { next(error); }
});

// --- 4. TRUCKER APIs ---
app.get('/api/loads/assigned', authenticateToken, async (req, res, next) => {
    try {
        const vendorId = req.user.userId;
        const query = `
            SELECT tl.*, im.item_name, ttm.truck_name,
                (SELECT COUNT(*) FROM bidding_history_log WHERE load_id = tl.load_id AND vendor_id = ?) as bid_attempts,
                CASE WHEN b.bid_id IS NOT NULL THEN (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.load_id = tl.load_id AND b2.bid_amount < b.bid_amount) ELSE NULL END AS my_rank
            FROM truck_loads tl
            JOIN trucker_assignments ta ON tl.requisition_id = ta.requisition_id
            JOIN item_master im ON tl.item_id = im.item_id
            JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id
            LEFT JOIN bids b ON tl.load_id = b.load_id AND b.vendor_id = ?
            WHERE ta.vendor_id = ? AND tl.status = 'Active'
            ORDER BY tl.requirement_date ASC, tl.load_id DESC`;
        const [loads] = await dbPool.query(query, [vendorId, vendorId, vendorId]);
        res.json({ success: true, data: loads });
    } catch (error) { next(error); }
});

app.post('/api/bids', authenticateToken, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { bids } = req.body;
        await connection.beginTransaction();
        let submittedCount = 0;
        for (const bid of bids) {
            const { loadId, bid_amount, comments } = bid;
            const vendorId = req.user.userId;

            await connection.query('DELETE FROM bids WHERE load_id = ? AND vendor_id = ?', [loadId, vendorId]);
            const [result] = await connection.query("INSERT INTO bids (load_id, vendor_id, bid_amount, comments, submitted_at) VALUES (?, ?, ?, ?, ?)", [loadId, vendorId, bid_amount, comments, new Date()]);
            await connection.query("INSERT INTO bidding_history_log (bid_id, load_id, vendor_id, bid_amount, submitted_at) VALUES (?, ?, ?, ?, ?)", [result.insertId, loadId, vendorId, bid_amount, new Date()]);
            submittedCount++;
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

app.get('/api/trucker/dashboard-stats', authenticateToken, async (req, res, next) => {
    try {
        const vendorId = req.user.userId;
        const queries = {
            assignedLoads: "SELECT COUNT(DISTINCT tl.load_id) as count FROM truck_loads tl JOIN trucker_assignments ta ON tl.requisition_id = ta.requisition_id WHERE ta.vendor_id = ? AND tl.status = 'Active'",
            submittedBids: "SELECT COUNT(DISTINCT load_id) as count FROM bidding_history_log WHERE vendor_id = ?",
            contractsWon: "SELECT COUNT(*) as count FROM awarded_contracts WHERE vendor_id = ?",
            needsBid: "SELECT COUNT(DISTINCT tl.load_id) as count FROM truck_loads tl JOIN trucker_assignments ta ON tl.requisition_id = ta.requisition_id WHERE ta.vendor_id = ? AND tl.status = 'Active' AND tl.load_id NOT IN (SELECT load_id FROM bids WHERE vendor_id = ?)"
        };
        const [ [[assignedResult]], [[submittedResult]], [[wonResult]], [[needsBidResult]] ] = await Promise.all([
            dbPool.query(queries.assignedLoads, [vendorId]),
            dbPool.query(queries.submittedBids, [vendorId]),
            dbPool.query(queries.contractsWon, [vendorId]),
            dbPool.query(queries.needsBid, [vendorId, vendorId])
        ]);
        res.json({ success: true, data: {
            assignedLoads: assignedResult.count || 0,
            submittedBids: submittedResult.count || 0,
            contractsWon: wonResult.count || 0,
            needsBid: needsBidResult.count || 0
        }});
    } catch (error) { next(error); }
});

// --- 5. ADMIN APIs ---
app.get('/api/loads/pending', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [groupedReqs] = await dbPool.query(`SELECT r.requisition_id, r.created_at, u.full_name as creator FROM requisitions r JOIN users u ON r.created_by = u.user_id WHERE r.status = 'Pending Approval' ORDER BY r.requisition_id DESC`);
        const [pendingLoads] = await dbPool.query(`SELECT tl.*, im.item_name, ttm.truck_name FROM truck_loads tl JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id WHERE tl.status = 'Pending Approval'`);
        const [allTruckers] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1");
        res.json({ success: true, data: { groupedReqs, pendingLoads, allTruckers } });
    } catch (error) { next(error); }
});

app.post('/api/loads/approve', authenticateToken, isAdmin, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { approvedLoadIds, truckerAssignments, requisitionId } = req.body;
        
        await connection.beginTransaction();
        if (approvedLoadIds && approvedLoadIds.length > 0) {
            await connection.query("UPDATE truck_loads SET status = 'Active' WHERE load_id IN (?)", [approvedLoadIds]);
        }
        await connection.query("UPDATE requisitions SET status = 'Processed', approved_at = ? WHERE requisition_id = ?", [new Date(), requisitionId]);
        
        if (truckerAssignments && truckerAssignments.length > 0) {
            await connection.query('DELETE FROM trucker_assignments WHERE requisition_id = ?', [requisitionId]);
            const values = truckerAssignments.map(vId => [requisitionId, vId, new Date()]);
            await connection.query('INSERT INTO trucker_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]);
        }
        await connection.commit();
        res.json({ success: true, message: 'Load requests processed successfully!' });
    } catch (error) {
        if (connection) await connection.rollback();
        next(error);
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/admin/dashboard-stats', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const queries = {
            activeLoads: "SELECT COUNT(*) as count FROM truck_loads WHERE status = 'Active'",
            pendingUsers: "SELECT COUNT(*) as count FROM pending_users",
            pendingLoads: "SELECT COUNT(*) as count FROM truck_loads WHERE status = 'Pending Approval'",
            awardedContracts: "SELECT COUNT(*) as count FROM awarded_contracts"
        };
        const [ [[activeResult]], [[pendingUsersResult]], [[pendingLoadsResult]], [[awardedResult]] ] = await Promise.all([
            dbPool.query(queries.activeLoads),
            dbPool.query(queries.pendingUsers),
            dbPool.query(queries.pendingLoads),
            dbPool.query(queries.awardedContracts)
        ]);
        res.json({ success: true, data: {
            activeLoads: activeResult.count || 0,
            pendingUsers: pendingUsersResult.count || 0,
            pendingLoads: pendingLoadsResult.count || 0,
            awardedContracts: awardedResult.count || 0
        }});
    } catch (error) { next(error); }
});

app.get('/api/admin/awarded-contracts', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [contracts] = await dbPool.query(`
            SELECT ac.load_id, ac.awarded_amount, ac.awarded_date, u.full_name as trucker_name, tl.loading_point_address, tl.unloading_point_address
            FROM awarded_contracts ac
            JOIN users u ON ac.vendor_id = u.user_id
            JOIN truck_loads tl ON ac.load_id = tl.load_id
            ORDER BY ac.awarded_date DESC
        `);
        res.json({ success: true, data: contracts });
    } catch (error) { next(error); }
});

// --- 6. USER MANAGEMENT (Admin) ---
app.get('/api/users/pending', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [rows] = await dbPool.query(`SELECT * FROM pending_users ORDER BY temp_id DESC`);
        // Map DB roles to frontend roles
        const data = rows.map(u => ({...u, role: u.role === 'Vendor' ? 'Trucker' : 'Shipper'}));
        res.json({ success: true, data });
    } catch (error) { next(error); }
});

app.post('/api/users/approve', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { temp_id } = req.body;
        const [[pendingUser]] = await dbPool.query('SELECT * FROM pending_users WHERE temp_id = ?', [temp_id]);
        if (!pendingUser) return res.status(404).json({ success: false, message: 'User not found' });
        
        await dbPool.query('INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)', 
            [pendingUser.full_name, pendingUser.email, pendingUser.password, pendingUser.role, pendingUser.company_name, pendingUser.contact_number, pendingUser.gstin]);
        
        await dbPool.query('DELETE FROM pending_users WHERE temp_id = ?', [temp_id]);
        res.json({ success: true, message: 'User approved!' });
    } catch (error) { next(error); }
});

app.delete('/api/pending-users/:id', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        await dbPool.query('DELETE FROM pending_users WHERE temp_id = ?', [req.params.id]);
        res.json({ success: true, message: 'Pending user rejected.' });
    } catch (error) { next(error); }
});

app.get('/api/users', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [rows] = await dbPool.query(`SELECT user_id, full_name, email, role, company_name, contact_number, gstin FROM users ORDER BY full_name`);
        const data = rows.map(u => ({...u, role: u.role === 'Vendor' ? 'Trucker' : (u.role === 'User' ? 'Shipper' : u.role)}));
        res.json({ success: true, data });
    } catch (error) { next(error); }
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { full_name, email, password, role, company_name, contact_number, gstin } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const dbRole = (role === 'Trucker') ? 'Vendor' : (role === 'Shipper' ? 'User' : role);
        await dbPool.query('INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)',
            [full_name, email, hashedPassword, dbRole, company_name, contact_number, gstin]);
        res.status(201).json({ success: true, message: 'User created successfully.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' });
        next(error);
    }
});

app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { full_name, email, role, company_name, contact_number, gstin, password } = req.body;
        const dbRole = (role === 'Trucker') ? 'Vendor' : (role === 'Shipper' ? 'User' : role);
        
        let query = 'UPDATE users SET full_name=?, email=?, role=?, company_name=?, contact_number=?, gstin=?';
        let params = [full_name, email, dbRole, company_name, contact_number, gstin];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += ', password_hash=?';
            params.push(hashedPassword);
        }
        query += ' WHERE user_id=?';
        params.push(id);
        
        await dbPool.query(query, params);
        res.json({ success: true, message: 'User updated successfully.' });
    } catch (error) { next(error); }
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        await dbPool.query('DELETE FROM users WHERE user_id = ?', [req.params.id]);
        res.json({ success: true, message: 'User deleted successfully.' });
    } catch (error) { next(error); }
});


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
