const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const xlsx = require('xlsx');
const sgMail = require('@sendgrid/mail');
require('dotenv').config();
const path = require('path');
const fs = require('fs/promises');
const os = require('os');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
const upload = multer({ storage: multer.memoryStorage() });

const ERROR_REPORTS_DIR = path.join(os.tmpdir(), 'error_reports');

if (process.env.SENDGRID_API_KEY) {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    console.log('✅ SendGrid API Key configured.');
} else {
    console.warn('⚠️ SENDGRID_API_KEY not found in .env file. Email notifications will be disabled.');
}

(async () => {
    try {
        await fs.access(ERROR_REPORTS_DIR);
    } catch (e) {
        await fs.mkdir(ERROR_REPORTS_DIR, { recursive: true });
        console.log(`✅ Created '${ERROR_REPORTS_DIR}' directory.`);
    }
})();

app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE || 'logistics_db',
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 20000,
    dateStrings: true,
    
    afterConnect: (connection, callback) => {
        connection.query("SET time_zone = '+05:30';", (err) => {
            if (err) {
                console.error("FATAL ERROR: Failed to set timezone for DB connection:", err);
                callback(err, connection);
            } else {
                callback(null, connection);
            }
        });
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'Unauthorized' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Forbidden: Invalid Token' });
        req.user = user;
        next();
    });
};

const authenticatePowerBi = (req, res, next) => {
    const apiKey = req.headers['x-api-key']; 
    const serverApiKey = process.env.POWER_BI_API_KEY;

    if (!apiKey) {
        return res.status(401).json({ success: false, message: 'API Key is missing.' });
    }
    
    if (!serverApiKey) {
        console.error('FATAL: POWER_BI_API_KEY is not set in environment variables.');
        return res.status(500).json({ success: false, message: 'Server configuration error.' });
    }

    if (apiKey === serverApiKey) {
        next();
    } else {
        return res.status(403).json({ success: false, message: 'Forbidden: Invalid API Key.' });
    }
};


const isAdmin = (req, res, next) => {
    if (!['Admin', 'Super Admin'].includes(req.user.role)) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
};

const sendAwardNotificationEmails = async (awardedBids) => {
    if (!process.env.SENDGRID_API_KEY || !process.env.SENDER_EMAIL) { return; }
    if (!awardedBids || awardedBids.length === 0) { return; }

    const loadIds = awardedBids.map(b => b.load_id);
    
    const [loadDetailsRows] = await dbPool.query(`SELECT tl.load_id, tl.loading_point_address, tl.unloading_point_address, tl.approx_weight_tonnes, tl.requirement_date, im.item_name, ttm.truck_name, tl.remarks as load_remarks FROM truck_loads tl JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id WHERE tl.load_id IN (?)`, [loadIds]);
    
    const loadDetailsMap = new Map(loadDetailsRows.map(row => [row.load_id, row]));
    const fullAwardedBids = awardedBids.map(bid => ({ ...bid, ...loadDetailsMap.get(bid.load_id) }));
    
    const notificationsByVendor = {};
    for (const bid of fullAwardedBids) {
        if (!notificationsByVendor[bid.vendor_id]) {
            notificationsByVendor[bid.vendor_id] = { 
                vendorName: bid.trucker_name, 
                vendorCompanyName: bid.company_name, 
                vendorEmail: bid.trucker_email, 
                loads: [], 
                totalValue: 0, 
                adminRemarks: bid.remarks 
            };
        }
        notificationsByVendor[bid.vendor_id].loads.push(bid);
        notificationsByVendor[bid.vendor_id].totalValue += parseFloat(bid.final_amount);
    }

    const [adminRows] = await dbPool.query("SELECT email FROM users WHERE role IN ('Admin', 'Super Admin') AND is_active = 1");
    const adminEmails = adminRows.map(a => a.email);

    for (const vendorId in notificationsByVendor) {
        const notification = notificationsByVendor[vendorId];
        const subject = `Congratulations! You've been awarded ${notification.loads.length} new load(s) from Laser Power Truck Bidding`;

        const loadsHtml = notification.loads.map(load => {
            const reqDate = new Date(load.requirement_date).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
            return `<tr>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; text-align: center; word-wrap: break-word;">${load.load_id}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; word-wrap: break-word;">${load.loading_point_address}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; word-wrap: break-word;">${load.unloading_point_address}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; word-wrap: break-word;">${load.item_name}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; word-wrap: break-word;">${load.truck_name}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; text-align: right; word-wrap: break-word;">${parseFloat(load.approx_weight_tonnes).toFixed(2)}T</td>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; text-align: center; word-wrap: break-word;">${reqDate}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; text-align: right; font-weight: bold; word-wrap: break-word;">₹${parseFloat(load.final_amount).toLocaleString('en-IN')}</td>
                            <td style="padding: 10px; border-bottom: 1px solid #dee2e6; word-wrap: break-word;">${load.load_remarks || '-'}</td>
                        </tr>`;
        }).join('');
        
        const htmlBody = `<div style="font-family: Arial, sans-serif; max-width: 960px; margin: auto; border: 1px solid #ddd; border-radius: 8px;"><div style="background-color: #172B4D; color: white; padding: 20px; text-align: center; border-top-left-radius: 8px; border-top-right-radius: 8px;"><h1 style="margin: 0;">Contract Awarded</h1></div><div style="padding: 20px;"><p>Dear ${notification.vendorCompanyName || notification.vendorName},</p><p>Congratulations! We are pleased to inform you that you have been awarded the following load(s):</p><div style="overflow-x: auto; -webkit-overflow-scrolling: touch;"><table style="width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px;"><thead style="background-color: #f8f9fa;"><tr><th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Load ID</th><th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Loading Point</th><th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Unloading Point</th><th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Material</th><th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Truck</th><th style="padding: 10px; text-align: right; border-bottom: 2px solid #dee2e6;">Weight</th><th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Req. Date</th><th style="padding: 10px; text-align: right; border-bottom: 2px solid #dee2e6;">Your Awarded Bid</th><th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Load Remarks</th></tr></thead><tbody>${loadsHtml}</tbody><tfoot><tr style="font-weight: bold; background-color: #f8f9fa;"><td colspan="8" style="padding: 10px; text-align: right;">Total Value:</td><td style="padding: 10px; text-align: right;">₹${notification.totalValue.toLocaleString('en-IN')}</td></tr></tfoot></table></div><p style="margin-top: 15px;"><b>Admin Remarks:</b> ${notification.adminRemarks || 'N/A'}</p><p style="margin-top: 25px;">Our team will contact you shortly regarding the next steps. Thank you for your participation.</p><p>Sincerely,<br/><b>The Laser Power Truck Bidding Team</b></p></div></div>`;
        try {
            await sgMail.send({ to: notification.vendorEmail, from: { name: "Laser Power Truck Bidding", email: process.env.SENDER_EMAIL }, cc: adminEmails, subject: subject, html: htmlBody });
        } catch (error) {
            console.error(`❌ Failed to send award email to ${notification.vendorEmail}:`, error.response ? error.response.body : error);
        }
    }
};

async function processBulkUpload(uploadId, jsonData, userId) {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const [itemRows] = await connection.query('SELECT item_id, item_name FROM item_master WHERE is_active = 1');
        const [truckRows] = await connection.query('SELECT truck_type_id, truck_name FROM truck_type_master WHERE is_active = 1');
        const itemMap = new Map(itemRows.map(i => [String(i.item_name).trim().toLowerCase(), i.item_id]));
        const truckMap = new Map(truckRows.map(t => [String(t.truck_name).trim().toLowerCase(), t.truck_type_id]));
        await connection.beginTransaction();
        const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', NOW())", [userId]);
        const reqId = reqResult.insertId;
        let successCount = 0;
        const errors = [];
        for (const row of jsonData) {
            const materialName = row.MaterialName ? String(row.MaterialName).trim().toLowerCase() : null;
            const truckName = row.TruckName ? String(row.TruckName).trim().toLowerCase() : null;
            const itemId = itemMap.get(materialName);
            const truckTypeId = truckMap.get(truckName);
            
            let requirementDate = row.RequirementDate;
            if (requirementDate instanceof Date) {
                const tzoffset = requirementDate.getTimezoneOffset() * 60000;
                const localDate = new Date(requirementDate.getTime() - tzoffset);
                requirementDate = localDate.toISOString().split('T')[0];
            } else if (typeof requirementDate === 'number') {
                const excelEpoch = new Date(1899, 11, 30);
                const jsDate = new Date(excelEpoch.getTime() + requirementDate * 86400000);
                const tzoffset = jsDate.getTimezoneOffset() * 60000;
                const localDate = new Date(jsDate.getTime() - tzoffset);
                requirementDate = localDate.toISOString().split('T')[0];
            }

            let errorReason = '';
            if (!row.LoadingPoint) errorReason = 'LoadingPoint is missing.';
            else if (!row.UnloadingPoint) errorReason = 'UnloadingPoint is missing.';
            else if (!itemId) errorReason = `MaterialName '${row.MaterialName}' not found or is inactive.`;
            else if (!truckTypeId) errorReason = `TruckName '${row.TruckName}' not found or is inactive.`;
            else if (!row.WeightInTonnes) errorReason = 'WeightInTonnes is missing.';
            else if (!requirementDate) errorReason = 'RequirementDate is missing.';
            if (errorReason) {
                errors.push({ ...row, ErrorReason: errorReason });
                continue;
            }
            try {
                await connection.query(
                    `INSERT INTO truck_loads (requisition_id, created_by, loading_point_address, unloading_point_address, item_id, approx_weight_tonnes, truck_type_id, requirement_date, status, inhouse_requisition_no, remarks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending Approval', ?, ?)`,
                    [reqId, userId, row.LoadingPoint, row.UnloadingPoint, itemId, row.WeightInTonnes, truckTypeId, requirementDate, row.InhouseRequisitionNo, row.Remarks]
                );
                successCount++;
            } catch (dbError) {
                errors.push({ ...row, ErrorReason: `Database Error: ${dbError.message}` });
            }
        }
        await connection.commit();
        let finalStatus = 'FAILED';
        let errorFilePath = null;
        if (successCount === jsonData.length) {
            finalStatus = 'SUCCESS';
        } else if (successCount > 0) {
            finalStatus = 'PARTIAL';
        }
        if (errors.length > 0) {
            const errorFileName = `error_report_${uploadId}_${Date.now()}.xlsx`;
            errorFilePath = path.join('error_reports', errorFileName);
            const ws = xlsx.utils.json_to_sheet(errors);
            const wb = xlsx.utils.book_new();
            xlsx.utils.book_append_sheet(wb, ws, "Errors");
            await xlsx.writeFile(wb, path.join(ERROR_REPORTS_DIR, errorFileName));
        }
        await connection.query(
            "UPDATE bulk_upload_history SET status = ?, success_count = ?, error_count = ?, completed_at = NOW(), error_file_path = ? WHERE upload_id = ?",
            [finalStatus, successCount, errors.length, errorFilePath, uploadId]
        );
    } catch (error) {
        console.error(`Error processing uploadId ${uploadId}:`, error);
        if (connection) {
            await connection.rollback();
            await connection.query("UPDATE bulk_upload_history SET status = 'FAILED', completed_at = NOW() WHERE upload_id = ?", [uploadId]);
        }
    } finally {
        if (connection) connection.release();
        console.log(`✅ Finished processing for uploadId ${uploadId}.`);
    }
}

// All API routes
const apiRouter = express.Router();


// ====================================================================
// FINAL: Master API route for Power BI to fetch all tables at once
// ====================================================================
apiRouter.get('/powerbi/all-data', authenticatePowerBi, async (req, res, next) => {
    try {
        // We will run all queries in parallel for maximum efficiency
        const [
            [allLoads],
            [awardedContracts],
            [vendors],
            [items],
            [truckTypes]
        ] = await Promise.all([
            // Query 1: Get all loads
            dbPool.query(`
                SELECT tl.*, im.item_name, ttm.truck_name 
                FROM truck_loads tl
                LEFT JOIN item_master im ON tl.item_id = im.item_id
                LEFT JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id
                ORDER BY tl.load_id DESC
            `),
            // Query 2: Get all awarded contracts
            dbPool.query(`
                SELECT ac.*, u.full_name AS trucker_name, u.company_name, tl.loading_point_address, tl.unloading_point_address
                FROM awarded_contracts ac
                LEFT JOIN users u ON ac.vendor_id = u.user_id
                LEFT JOIN truck_loads tl ON ac.load_id = tl.load_id
                ORDER BY ac.awarded_date DESC
            `),
            // Query 3: Get all vendors (truckers)
            dbPool.query(`
                SELECT user_id, full_name, email, company_name, contact_number, gstin 
                FROM users WHERE role = 'Vendor'
            `),
            // Query 4: Get item master
            dbPool.query(`SELECT * FROM item_master`),
            // Query 5: Get truck type master
            dbPool.query(`SELECT * FROM truck_type_master`)
        ]);

        // We package all results into a single JSON object.
        // Each key in this object will become a table in Power BI.
        res.json({
            all_loads: allLoads,
            awarded_contracts: awardedContracts,
            vendors: vendors,
            items_master: items,
            truck_types_master: truckTypes
        });

    } catch (error) {
        next(error);
    }
});


// ====================================================================
// Original Application API routes
// ====================================================================
apiRouter.post('/bids', authenticateToken, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { bids } = req.body; await connection.beginTransaction(); const skippedBids = []; for (const bid of bids) { const vendorId = req.user.userId; const [[loadDetails]] = await connection.query(`SELECT status, (CONVERT_TZ(NOW(), 'SYSTEM', '+05:30') >= bidding_start_time OR bidding_start_time IS NULL) as is_after_start, (CONVERT_TZ(NOW(), 'SYSTEM', '+05:30') <= bidding_end_time OR bidding_end_time IS NULL) as is_before_end FROM truck_loads WHERE load_id = ?`, [bid.loadId]); if (!loadDetails || loadDetails.status !== 'Active') { skippedBids.push(`Load ID ${bid.loadId} (Not active)`); continue; } if (!(loadDetails.is_after_start && loadDetails.is_before_end)) { skippedBids.push(`Load ID ${bid.loadId} (Bidding window closed)`); continue; } await connection.query('DELETE FROM bids WHERE load_id = ? AND vendor_id = ?', [bid.loadId, vendorId]); const [result] = await connection.query("INSERT INTO bids (load_id, vendor_id, bid_amount, submitted_at) VALUES (?, ?, ?, NOW())", [bid.loadId, vendorId, bid.bid_amount]); await connection.query("INSERT INTO bidding_history_log (bid_id, load_id, vendor_id, bid_amount) VALUES (?, ?, ?, ?)", [result.insertId, bid.loadId, vendorId, bid.bid_amount]); } await connection.commit(); let message = `${bids.length - skippedBids.length} bid(s) submitted successfully.`; if (skippedBids.length > 0) { message += ` Skipped bids: ${skippedBids.join(', ')}.`; } res.json({ success: true, message }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
apiRouter.post('/messages', authenticateToken, async (req, res, next) => { try { const { recipientId, messageBody } = req.body; await dbPool.query('INSERT INTO messages (sender_id, recipient_id, message_body, timestamp, status) VALUES (?, ?, ?, NOW(), ?)', [req.user.userId, recipientId, messageBody, 'sent']); res.status(201).json({ success: true, message: 'Message sent' }); } catch(e) { next(e); }});
apiRouter.post('/contracts/award', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { bids } = req.body; if (!bids || bids.length === 0) { return res.status(400).json({ success: false, message: 'No bids provided to award.' }); } const vendorIds = [...new Set(bids.map(b => b.vendor_id))]; const [users] = await dbPool.query('SELECT user_id, full_name, email, company_name FROM users WHERE user_id IN (?)', [vendorIds]); const vendorInfoMap = new Map(users.map(user => [user.user_id, { trucker_name: user.full_name, trucker_email: user.email, company_name: user.company_name }])); const bidsForEmail = bids.map(bid => ({ ...bid, ...vendorInfoMap.get(bid.vendor_id) })); await connection.beginTransaction(); for (const bid of bids) { await connection.query( "UPDATE bids SET bid_amount = ? WHERE load_id = ? AND vendor_id = ?", [bid.final_amount, bid.load_id, bid.vendor_id] ); await connection.query("DELETE FROM awarded_contracts WHERE load_id = ?", [bid.load_id]); await connection.query( "INSERT INTO awarded_contracts (load_id, requisition_id, vendor_id, awarded_amount, remarks, awarded_date) VALUES (?, ?, ?, ?, ?, NOW())", [bid.load_id, bid.requisition_id, bid.vendor_id, bid.final_amount, bid.remarks] ); await connection.query("UPDATE truck_loads SET status = 'Awarded' WHERE load_id = ?", [bid.load_id]); } await connection.commit(); sendAwardNotificationEmails(bidsForEmail).catch(err => console.error("Email sending failed after award:", err)); res.json({ success: true, message: 'Contract(s) awarded successfully.' }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
apiRouter.get('/master-data/truck-types', authenticateToken, async (req, res, next) => { try { const [d] = await dbPool.query("SELECT * FROM truck_type_master ORDER BY truck_name"); res.json({ success: true, data: d }); } catch (e) { next(e); }});
apiRouter.get('/master-data/items', authenticateToken, async (req, res, next) => { try { const [d] = await dbPool.query("SELECT * FROM item_master ORDER BY item_name"); res.json({ success: true, data: d }); } catch (e) { next(e); }});
apiRouter.post('/login', async (req, res, next) => { try { const { email, password } = req.body; const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]); if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials or account inactive.' }); const user = rows[0]; const match = await bcrypt.compare(password, user.password_hash); if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' }); if (user.role === 'User') user.role = 'Shipper'; if (user.role === 'Vendor') user.role = 'Trucker'; const payload = { userId: user.user_id, role: user.role, fullName: user.full_name, email: user.email }; const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' }); delete user.password_hash; res.json({ success: true, token, user }); } catch (error) { next(error); }});
apiRouter.post('/register', async (req, res, next) => { try { const { FullName, Email, Password, Role, CompanyName, ContactNumber, GSTIN } = req.body; const hashedPassword = await bcrypt.hash(Password, 10); const dbRole = (Role === 'Trucker') ? 'Vendor' : 'User'; await dbPool.query('INSERT INTO pending_users (full_name, email, password, role, company_name, contact_number, gstin) VALUES (?, ?, ?, ?, ?, ?, ?)', [FullName, Email, hashedPassword, dbRole, CompanyName, ContactNumber, GSTIN]); res.status(201).json({ success: true, message: 'Registration successful! Awaiting admin approval.' }); } catch (error) { if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' }); next(error); }});
apiRouter.post('/loads', authenticateToken, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { items } = req.body; await connection.beginTransaction(); const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', ?)", [req.user.userId, new Date()]); const reqId = reqResult.insertId; const parsedLoads = JSON.parse(items); for (const load of parsedLoads) { await connection.query(`INSERT INTO truck_loads (requisition_id, created_by, loading_point_address, unloading_point_address, item_id, approx_weight_tonnes, truck_type_id, requirement_date, status, inhouse_requisition_no, remarks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending Approval', ?, ?)`, [reqId, req.user.userId, load.loading_point_address, load.unloading_point_address, load.item_id, load.approx_weight_tonnes, load.truck_type_id, load.requirement_date, load.inhouse_requisition_no, load.remarks]); } await connection.commit(); res.status(201).json({ success: true, message: 'Load request submitted successfully!' }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
apiRouter.get('/shipper/status', authenticateToken, async (req, res, next) => { try { const [myReqs] = await dbPool.query('SELECT * FROM requisitions WHERE created_by = ? ORDER BY requisition_id DESC', [req.user.userId]); if (myReqs.length === 0) return res.json({ success: true, data: [] }); const reqIds = myReqs.map(r => r.requisition_id); const [loads] = await dbPool.query(`SELECT tl.*, ac.awarded_amount, u.full_name as awarded_vendor, im.item_name FROM truck_loads tl LEFT JOIN awarded_contracts ac ON tl.load_id = ac.load_id LEFT JOIN users u ON ac.vendor_id = u.user_id JOIN item_master im ON tl.item_id = im.item_id WHERE tl.requisition_id IN (?) ORDER BY tl.load_id ASC`, [reqIds]); const finalData = myReqs.map(req => ({ ...req, loads: loads.filter(load => load.requisition_id === req.requisition_id) })); res.json({ success: true, data: finalData }); } catch (error) { next(error); }});
apiRouter.get('/loads/assigned', authenticateToken, async (req, res, next) => { try { const vendorId = req.user.userId; const { startDate, endDate } = req.query; let query = ` SELECT tl.*, im.item_name, ttm.truck_name, (SELECT COUNT(*) FROM bidding_history_log WHERE load_id = tl.load_id AND vendor_id = ?) as bid_attempts, (SELECT JSON_ARRAYAGG(JSON_OBJECT('bid_amount', bhl.bid_amount, 'rank', ( SELECT COUNT(DISTINCT b_rank.vendor_id) + 1 FROM bids b_rank WHERE b_rank.load_id = bhl.load_id AND b_rank.bid_amount < bhl.bid_amount ))) FROM bidding_history_log bhl WHERE bhl.load_id = tl.load_id AND bhl.vendor_id = ? ORDER BY bhl.submitted_at ASC) AS my_bid_history, CASE WHEN b.bid_id IS NOT NULL THEN (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.load_id = tl.load_id AND b2.bid_amount < b.bid_amount) ELSE NULL END AS my_rank FROM truck_loads tl JOIN trucker_assignments ta ON tl.requisition_id = ta.requisition_id JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id LEFT JOIN bids b ON tl.load_id = b.load_id AND b.vendor_id = ? WHERE ta.vendor_id = ? AND tl.status = 'Active'`; const params = [vendorId, vendorId, vendorId, vendorId]; if (startDate) { query += ` AND tl.requirement_date >= ?`; params.push(startDate); } if (endDate) { query += ` AND tl.requirement_date <= ?`; params.push(endDate); } query += ` ORDER BY tl.requirement_date ASC, tl.load_id DESC`; const [loads] = await dbPool.query(query, params); res.json({ success: true, data: loads }); } catch (error) { next(error); }});
apiRouter.get('/trucker/dashboard-stats', authenticateToken, async (req, res, next) => { try { const vendorId = req.user.userId; const queries = { assignedLoads: "SELECT COUNT(DISTINCT tl.load_id) as count FROM truck_loads tl JOIN trucker_assignments ta ON tl.requisition_id = ta.requisition_id WHERE ta.vendor_id = ? AND tl.status = 'Active'", submittedBids: "SELECT COUNT(DISTINCT load_id) as count FROM bidding_history_log WHERE vendor_id = ?", contractsWon: "SELECT COUNT(*) as count, SUM(awarded_amount) as totalValue FROM awarded_contracts WHERE vendor_id = ?", needsBid: "SELECT COUNT(DISTINCT tl.load_id) as count FROM truck_loads tl JOIN trucker_assignments ta ON tl.requisition_id = ta.requisition_id WHERE ta.vendor_id = ? AND tl.status = 'Active' AND tl.load_id NOT IN (SELECT load_id FROM bids WHERE vendor_id = ?)", l1Bids: "SELECT COUNT(*) as count FROM (SELECT load_id FROM bids WHERE vendor_id = ? AND bid_amount = (SELECT MIN(bid_amount) FROM bids b2 WHERE b2.load_id = bids.load_id) GROUP BY load_id) as l1_bids", avgRank: `SELECT AVG(t.rank) as avg_rank FROM (SELECT (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.load_id = b.load_id AND b2.bid_amount < b.bid_amount) as \`rank\` FROM bids b WHERE b.vendor_id = ?) as t`, recentBids: `SELECT bhl.load_id, bhl.bid_amount, tl.status as status FROM bidding_history_log bhl JOIN truck_loads tl ON bhl.load_id = tl.load_id WHERE bhl.vendor_id = ? ORDER BY bhl.submitted_at DESC LIMIT 5` }; const [ [[assignedResult]], [[submittedResult]], [[wonResult]], [[needsBidResult]], [[l1BidsResult]], [[avgRankResult]], [recentBids] ] = await Promise.all([ dbPool.query(queries.assignedLoads, [vendorId]), dbPool.query(queries.submittedBids, [vendorId]), dbPool.query(queries.contractsWon, [vendorId]), dbPool.query(queries.needsBid, [vendorId, vendorId]), dbPool.query(queries.l1Bids, [vendorId]), dbPool.query(queries.avgRank, [vendorId]), dbPool.query(queries.recentBids, [vendorId]) ]); const totalBids = submittedResult.count; const kpis = [ { title: 'Win Rate', value: totalBids > 0 ? `${((wonResult.count / totalBids) * 100).toFixed(1)}%` : '0%', icon: 'fa-tachometer-alt', color: 'primary' }, { title: 'Total Value Won', value: `₹${(wonResult.totalValue || 0).toLocaleString('en-IN')}`, icon: 'fa-handshake', color: 'success' }, { title: 'Avg. Bid Rank', value: avgRankResult.avg_rank ? parseFloat(avgRankResult.avg_rank).toFixed(1) : 'N/A', icon: 'fa-balance-scale', color: 'warning' }, { title: 'L1 Bid Count', value: l1BidsResult.count || '0', icon: 'fa-chart-line', color: 'danger' } ]; res.json({ success: true, data: { assignedLoads: assignedResult.count||0, submittedBids: totalBids||0, contractsWon: wonResult.count||0, needsBid: needsBidResult.count||0, kpis, recentBids }}); } catch (error) { next(error); }});
apiRouter.get('/trucker/bidding-history', authenticateToken, async (req, res, next) => { try { const { status, startDate, endDate } = req.query; const vendorId = req.user.userId; let query = ` SELECT bhl.*, u.full_name as trucker_name, u.company_name, tl.loading_point_address, tl.unloading_point_address, tl.status AS status, tl.requirement_date, tl.inhouse_requisition_no, tl.remarks, im.item_name, ttm.truck_name, tl.approx_weight_tonnes, (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.load_id = bhl.load_id AND b2.bid_amount < bhl.bid_amount) as \`rank\`, CASE WHEN tl.status = 'Awarded' THEN (SELECT MIN(b3.bid_amount) FROM bids b3 WHERE b3.load_id = bhl.load_id) ELSE NULL END as l1_bid FROM bidding_history_log bhl JOIN truck_loads tl ON bhl.load_id = tl.load_id JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id JOIN users u ON bhl.vendor_id = u.user_id WHERE bhl.vendor_id = ?`; const params = [vendorId]; if (status) { query += ' AND tl.status = ?'; params.push(status); } if (startDate) { query += ' AND DATE(bhl.submitted_at) >= ?'; params.push(startDate); } if (endDate) { query += ' AND DATE(bhl.submitted_at) <= ?'; params.push(endDate); } query += ' ORDER BY bhl.submitted_at DESC'; const [bids] = await dbPool.query(query, params); res.json({ success: true, data: bids }); } catch (error) { next(error); }});
apiRouter.get('/trucker/awarded-contracts', authenticateToken, async (req, res, next) => { try { const { startDate, endDate } = req.query; const vendorId = req.user.userId; let query = `SELECT ac.load_id, ac.awarded_amount, ac.awarded_date, tl.loading_point_address, tl.unloading_point_address, tl.requirement_date, tl.approx_weight_tonnes, im.item_name, ttm.truck_name FROM awarded_contracts ac JOIN truck_loads tl ON ac.load_id = tl.load_id LEFT JOIN item_master im ON tl.item_id = im.item_id LEFT JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id WHERE ac.vendor_id = ?`; const params = [vendorId]; if (startDate) { query += ' AND DATE(ac.awarded_date) >= ?'; params.push(startDate); } if (endDate) { query += ' AND DATE(ac.awarded_date) <= ?'; params.push(endDate); } query += ' ORDER BY ac.awarded_date DESC'; const [contracts] = await dbPool.query(query, params); res.json({ success: true, data: contracts }); } catch (error) { next(error); }});
apiRouter.get('/loads/pending', authenticateToken, isAdmin, async (req, res, next) => { try { const [groupedReqs] = await dbPool.query(`SELECT r.requisition_id, r.created_at, COALESCE(u.full_name, 'Deleted User') as creator FROM requisitions r LEFT JOIN users u ON r.created_by = u.user_id WHERE r.status = 'Pending Approval' ORDER BY r.requisition_id DESC`); const [pendingLoads] = await dbPool.query(`SELECT tl.*, COALESCE(im.item_name, 'N/A') as item_name, COALESCE(ttm.truck_name, 'N/A') as truck_name FROM truck_loads tl LEFT JOIN item_master im ON tl.item_id = im.item_id LEFT JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id WHERE tl.status = 'Pending Approval'`); const [allTruckers] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1"); res.json({ success: true, data: { groupedReqs, pendingLoads, allTruckers } }); } catch (error) { next(error); }});
apiRouter.get('/admin/dashboard-stats', authenticateToken, isAdmin, async (req, res, next) => {  try {  const queries = { activeLoads: "SELECT COUNT(*) as count FROM truck_loads WHERE status = 'Active'", pendingUsers: "SELECT COUNT(*) as count FROM pending_users", pendingLoads: "SELECT COUNT(*) as count FROM truck_loads WHERE status = 'Pending Approval'", awardedContracts: "SELECT COUNT(*) as count FROM awarded_contracts", biddingActivity: `SELECT u.full_name, COUNT(b.bid_id) as bid_count FROM bids b JOIN users u ON b.vendor_id = u.user_id GROUP BY b.vendor_id ORDER BY bid_count DESC LIMIT 5`, loadTrends: `SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(requisition_id) as count FROM requisitions GROUP BY month ORDER BY month DESC LIMIT 6` };  const [ [[activeResult]], [[pendingUsersResult]], [[pendingLoadsResult]], [[awardedResult]], [biddingActivity], [loadTrends] ] = await Promise.all([ dbPool.query(queries.activeLoads), dbPool.query(queries.pendingUsers), dbPool.query(queries.pendingLoads), dbPool.query(queries.awardedContracts), dbPool.query(queries.biddingActivity), dbPool.query(queries.loadTrends) ]);  res.json({ success: true, data: { activeLoads: activeResult.count||0, pendingUsers: pendingUsersResult.count||0, pendingLoads: pendingLoadsResult.count||0, awardedContracts: awardedResult.count||0, charts: { loadTrends: { labels: loadTrends.map(r => r.month).reverse(), data: loadTrends.map(r => r.count).reverse() }, biddingActivity: { labels: biddingActivity.map(r => r.full_name), data: biddingActivity.map(r => r.bid_count) } } }});  } catch (error) {  next(error);  }});
apiRouter.post('/loads/approve', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { approvedLoadIds, truckerAssignments, requisitionId, biddingStartTime, biddingDurationMinutes } = req.body; if (!biddingStartTime || !biddingDurationMinutes) { return res.status(400).json({ success: false, message: 'Bidding Start Time and Duration are mandatory.' }); } const startTime = new Date(biddingStartTime); const endTime = new Date(startTime.getTime() + parseInt(biddingDurationMinutes, 10) * 60000); await connection.beginTransaction(); if (approvedLoadIds && approvedLoadIds.length > 0) { await connection.query("UPDATE truck_loads SET status = 'Active', bidding_start_time = ?, bidding_end_time = ? WHERE load_id IN (?)", [startTime, endTime, approvedLoadIds]); } await connection.query("UPDATE requisitions SET status = 'Processed', approved_at = NOW() WHERE requisition_id = ?", [requisitionId]); if (truckerAssignments && truckerAssignments.length > 0) { await connection.query('DELETE FROM trucker_assignments WHERE requisition_id = ?', [requisitionId]); const values = truckerAssignments.map(vId => [requisitionId, vId, new Date()]); await connection.query('INSERT INTO trucker_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]); } await connection.commit(); res.json({ success: true, message: 'Load requests processed successfully!' }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
apiRouter.get('/admin/awarded-contracts', authenticateToken, isAdmin, async (req, res, next) => { try { const { startDate, endDate } = req.query; let query = ` SELECT ac.load_id, ac.requisition_id, ac.awarded_amount, ac.awarded_date, u.full_name as trucker_name, u.email as trucker_email, u.contact_number as trucker_contact, tl.loading_point_address, tl.unloading_point_address, tl.requirement_date, tl.approx_weight_tonnes, tl.inhouse_requisition_no, ac.remarks, im.item_name, ttm.truck_name FROM awarded_contracts ac JOIN users u ON ac.vendor_id = u.user_id JOIN truck_loads tl ON ac.load_id = tl.load_id LEFT JOIN item_master im ON tl.item_id = im.item_id LEFT JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id`; const params = []; const whereClauses = []; if (startDate) { whereClauses.push('DATE(ac.awarded_date) >= ?'); params.push(startDate); } if (endDate) { whereClauses.push('DATE(ac.awarded_date) <= ?'); params.push(endDate); } if(whereClauses.length > 0) { query += ` WHERE ${whereClauses.join(' AND ')}`; } query += ' ORDER BY ac.awarded_date DESC'; const [contracts] = await dbPool.query(query, params); res.json({ success: true, data: contracts }); } catch (error) { next(error); }});
apiRouter.get('/admin/all-loads', authenticateToken, isAdmin, async (req, res, next) => { try { const { status, startDate, endDate } = req.query; let query = ` SELECT tl.*, im.item_name, ttm.truck_name, l1_details.l1_bid, l1_details.l1_trucker, (SELECT GROUP_CONCAT(u_assign.full_name SEPARATOR ', ') FROM trucker_assignments ta JOIN users u_assign ON ta.vendor_id = u_assign.user_id WHERE ta.requisition_id = tl.requisition_id) as assigned_truckers FROM truck_loads tl JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id LEFT JOIN ( SELECT b.load_id, MIN(b.bid_amount) as l1_bid, (SELECT u.full_name FROM bids b_inner JOIN users u ON b_inner.vendor_id = u.user_id WHERE b_inner.load_id = b.load_id ORDER BY b_inner.bid_amount ASC, b_inner.submitted_at ASC LIMIT 1) as l1_trucker FROM bids b GROUP BY b.load_id ) AS l1_details ON tl.load_id = l1_details.load_id`; const params = []; const whereClauses = []; if (status) { whereClauses.push('tl.status = ?'); params.push(status); } if (startDate) { whereClauses.push('tl.requirement_date >= ?'); params.push(startDate); } if (endDate) { whereClauses.push('tl.requirement_date <= ?'); params.push(endDate); } if (whereClauses.length > 0) { query += ` WHERE ${whereClauses.join(' AND ')}`; } query += ' ORDER BY tl.load_id DESC'; const [loads] = await dbPool.query(query, params); res.json({ success: true, data: loads }); } catch (error) { next(error); }});
apiRouter.get('/admin/bidding-history', authenticateToken, isAdmin, async (req, res, next) => { try { const { startDate, endDate } = req.query; let query = ` SELECT bhl.*, u.full_name as trucker_name, u.company_name, tl.loading_point_address, tl.unloading_point_address, tl.requirement_date, tl.inhouse_requisition_no, tl.remarks, im.item_name, ttm.truck_name, tl.approx_weight_tonnes FROM bidding_history_log bhl JOIN users u ON bhl.vendor_id = u.user_id JOIN truck_loads tl ON bhl.load_id = tl.load_id JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id`; const params = []; const whereClauses = []; if (startDate) { whereClauses.push('DATE(bhl.submitted_at) >= ?'); params.push(startDate); } if (endDate) { whereClauses.push('DATE(bhl.submitted_at) <= ?'); params.push(endDate); } if (whereClauses.length > 0) { query += ` WHERE ${whereClauses.join(' AND ')}`; } query += ' ORDER BY bhl.submitted_at DESC'; const [bids] = await dbPool.query(query, params); res.json({ success: true, data: bids }); } catch (error) { next(error); }});
apiRouter.put('/admin/loads/bidding-time', authenticateToken, isAdmin, async (req, res, next) => { try { const { loadId, startTime, endTime } = req.body; if (!loadId) { return res.status(400).json({ success: false, message: 'Load ID is required.' }); } await dbPool.query("UPDATE truck_loads SET bidding_start_time = ?, bidding_end_time = ? WHERE load_id = ?", [startTime || null, endTime || null, loadId]); res.json({ success: true, message: 'Bidding time updated successfully.' }); } catch (error) { next(error); }});
apiRouter.put('/admin/loads/bulk-bidding-time', authenticateToken, isAdmin, async (req, res, next) => { try { const { loadIds, startTime, endTime } = req.body; if (!loadIds || loadIds.length === 0) { return res.status(400).json({ success: false, message: 'Please select at least one load.' }); } await dbPool.query("UPDATE truck_loads SET bidding_start_time = ?, bidding_end_time = ? WHERE load_id IN (?)", [startTime || null, endTime || null, loadIds]); res.json({ success: true, message: `${loadIds.length} load(s) have been updated with the new bidding time.` }); } catch (error) { next(error); }});
apiRouter.post('/admin/reports-data', authenticateToken, isAdmin, async (req, res, next) => { try { const { startDate, endDate } = req.body; const params = []; let whereClause = ''; if (startDate && endDate) { whereClause = ' WHERE ac.awarded_date BETWEEN ? AND ?'; params.push(startDate, `${endDate} 23:59:59`); } const queries = { detailedReport: ` SELECT ac.load_id, tl.inhouse_requisition_no, tl.loading_point_address, tl.unloading_point_address, im.item_name, tl.approx_weight_tonnes, ttm.truck_name, u.full_name as trucker_name, ac.awarded_amount, ac.awarded_date, tl.requirement_date, ac.remarks FROM awarded_contracts ac JOIN truck_loads tl ON ac.load_id = tl.load_id JOIN users u ON ac.vendor_id = u.user_id JOIN item_master im ON tl.item_id = im.item_id JOIN truck_type_master ttm ON tl.truck_type_id = ttm.truck_type_id ${whereClause} ORDER BY ac.awarded_date DESC`, kpis: `SELECT COALESCE(SUM(ac.awarded_amount), 0) AS totalSpend, COUNT(ac.load_id) as awardedLoads FROM awarded_contracts ac ${whereClause}`, topTruckers: `SELECT u.full_name as label, COUNT(ac.load_id) as value FROM awarded_contracts ac JOIN users u ON ac.vendor_id = u.user_id ${whereClause} GROUP BY label ORDER BY value DESC LIMIT 5`, spendOverTime: `SELECT DATE_FORMAT(ac.awarded_date, '%Y-%m-%d') as label, SUM(ac.awarded_amount) as value FROM awarded_contracts ac ${whereClause} GROUP BY label ORDER BY label`, spendByMaterial: `SELECT im.item_name as label, SUM(ac.awarded_amount) as value FROM awarded_contracts ac JOIN truck_loads tl ON ac.load_id = tl.load_id JOIN item_master im ON tl.item_id = im.item_id ${whereClause} GROUP BY label ORDER BY value DESC LIMIT 5` }; const [ [detailedReport], [[kpisResult]], [topTruckers], [spendOverTime], [spendByMaterial] ] = await Promise.all([ dbPool.query(queries.detailedReport, params), dbPool.query(queries.kpis, params), dbPool.query(queries.topTruckers, params), dbPool.query(queries.spendOverTime, params), dbPool.query(queries.spendByMaterial, params) ]); const kpis = kpisResult || { totalSpend: 0, awardedLoads: 0 }; res.json({ success: true, data: { kpis, detailedReport, chartsData: { topTruckers: { labels: topTruckers.map(t => t.label), data: topTruckers.map(t => t.value) }, spendOverTime: { labels: spendOverTime.map(s => s.label), data: spendOverTime.map(s => s.value) }, spendByMaterial: { labels: spendByMaterial.map(m => m.label), data: spendByMaterial.map(m => m.value) } } }}); } catch (error) { next(error); }});
apiRouter.post('/loads/bulk-approve', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { loadIds, truckerIds, biddingStartTime, biddingDurationMinutes } = req.body; if (!loadIds || loadIds.length === 0) { return res.status(400).json({ success: false, message: 'Please select at least one load to approve.' }); } if (!truckerIds || truckerIds.length === 0) { return res.status(400).json({ success: false, message: 'Please assign at least one trucker.' }); } if (!biddingStartTime || !biddingDurationMinutes) { return res.status(400).json({ success: false, message: 'Bidding Start Time and Duration are mandatory.' }); } const startTime = new Date(biddingStartTime); const endTime = new Date(startTime.getTime() + parseInt(biddingDurationMinutes, 10) * 60000); await connection.beginTransaction(); await connection.query("UPDATE truck_loads SET status = 'Active', bidding_start_time = ?, bidding_end_time = ? WHERE load_id IN (?) AND status = 'Pending Approval'", [startTime, endTime, loadIds]); const [reqs] = await dbPool.query("SELECT DISTINCT requisition_id FROM truck_loads WHERE load_id IN (?)", [loadIds]); const requisitionIds = reqs.map(r => r.requisition_id); if (requisitionIds.length > 0) { await connection.query("UPDATE requisitions SET status = 'Processed', approved_at = NOW() WHERE requisition_id IN (?)", [requisitionIds]); for (const reqId of requisitionIds) { await connection.query('DELETE FROM trucker_assignments WHERE requisition_id = ?', [reqId]); const assignmentValues = truckerIds.map(vId => [reqId, vId, new Date()]); await connection.query('INSERT INTO trucker_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [assignmentValues]); } } await connection.commit(); res.json({ success: true, message: `${loadIds.length} load(s) approved and assigned successfully!` }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
apiRouter.delete('/loads/:id', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { const { id } = req.params; connection = await dbPool.getConnection(); await connection.beginTransaction(); await connection.query("DELETE FROM bids WHERE load_id = ?", [id]); await connection.query("DELETE FROM awarded_contracts WHERE load_id = ?", [id]); const [result] = await connection.query("DELETE FROM truck_loads WHERE load_id = ?", [id]); await connection.commit(); if (result.affectedRows === 0) { return res.status(404).json({ success: false, message: 'Load not found.' }); } res.json({ success: true, message: 'Load and all related bids have been deleted.' }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
apiRouter.get('/loads/:id', authenticateToken, isAdmin, async (req, res, next) => { try { const { id } = req.params; const [rows] = await dbPool.query("SELECT * FROM truck_loads WHERE load_id = ?", [id]); if (!rows || rows.length === 0) { return res.status(404).json({ success: false, message: `Load with ID ${id} not found.` }); } const load = rows[0]; res.json({ success: true, data: load }); } catch (error) { console.error(`Error fetching load with ID ${req.params.id}:`, error); next(error); }});
apiRouter.put('/loads/:id', authenticateToken, isAdmin, async (req, res, next) => { try { const { id } = req.params; const { loading_point_address, unloading_point_address, item_id, truck_type_id, approx_weight_tonnes, requirement_date } = req.body; const [result] = await dbPool.query(`UPDATE truck_loads SET loading_point_address = ?, unloading_point_address = ?, item_id = ?, truck_type_id = ?, approx_weight_tonnes = ?, requirement_date = ? WHERE load_id = ?`, [loading_point_address, unloading_point_address, item_id, truck_type_id, approx_weight_tonnes, requirement_date, id]); if (result.affectedRows === 0) { return res.status(404).json({ success: false, message: 'Load not found.' }); } res.json({ success: true, message: 'Load updated successfully!' }); } catch (error) { next(error); }});
apiRouter.get('/admin/loads/:id/bids', authenticateToken, isAdmin, async (req, res, next) => { try { const [bids] = await dbPool.query(`SELECT b.*, u.full_name as trucker_name FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.load_id = ? ORDER BY b.bid_amount ASC`, [req.params.id]); const [[loadDetails]] = await dbPool.query('SELECT * FROM truck_loads WHERE load_id = ?', [req.params.id]); res.json({ success: true, data: { bids, loadDetails } }); } catch (error) { next(error); }});
apiRouter.post('/admin/bids-for-loads', authenticateToken, isAdmin, async (req, res, next) => { try { const { loadIds } = req.body; if (!loadIds || loadIds.length === 0) { return res.status(400).json({ success: false, message: 'No load IDs provided.' }); } const results = []; for (const loadId of loadIds) { const [bids] = await dbPool.query(`SELECT b.*, u.full_name as trucker_name, u.email as trucker_email, u.contact_number as trucker_contact FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.load_id = ? ORDER BY b.bid_amount ASC`, [loadId]); const [[loadDetails]] = await dbPool.query('SELECT tl.*, im.item_name FROM truck_loads tl JOIN item_master im ON tl.item_id = im.item_id WHERE tl.load_id = ?', [loadId]); results.push({ ...loadDetails, bids }); } res.json({ success: true, data: results }); } catch (error) { next(error); }});
apiRouter.get('/requisitions/:id/assignments', authenticateToken, isAdmin, async (req, res, next) => { try { const [allTruckers] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1 ORDER BY full_name"); const [assignedResult] = await dbPool.query("SELECT vendor_id FROM trucker_assignments WHERE requisition_id = ?", [req.params.id]); const assignedTruckerIds = assignedResult.map(a => a.vendor_id); res.json({ success: true, data: { allTruckers, assignedTruckerIds } }); } catch (error) { next(error); }});
apiRouter.put('/requisitions/:id/assignments', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); await connection.beginTransaction(); await connection.query('DELETE FROM trucker_assignments WHERE requisition_id = ?', [req.params.id]); if (req.body.truckerIds && req.body.truckerIds.length > 0) { const values = req.body.truckerIds.map(vId => [req.params.id, vId, new Date()]); await connection.query('INSERT INTO trucker_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]); } await connection.commit(); res.json({ success: true, message: 'Trucker assignments updated.' }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
apiRouter.post('/loads/reopen-bidding', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { loadIds, remarks, truckerIds } = req.body; await connection.beginTransaction(); const [reqIdsResult] = await dbPool.query('SELECT DISTINCT requisition_id FROM truck_loads WHERE load_id IN (?)', [loadIds]); const requisitionIds = reqIdsResult.map(r => r.requisition_id); await connection.query("UPDATE truck_loads SET status = 'Active' WHERE load_id IN (?)", [loadIds]); await connection.query("DELETE FROM awarded_contracts WHERE load_id IN (?)", [loadIds]); for (const reqId of requisitionIds) { await connection.query('DELETE FROM trucker_assignments WHERE requisition_id = ?', [reqId]); if (truckerIds && truckerIds.length > 0) { const values = truckerIds.map(vId => [reqId, vId, new Date()]); await connection.query('INSERT INTO trucker_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]); } } console.log(`Loads ${loadIds.join(',')} re-opened by ${req.user.fullName} with remarks: ${remarks}`); await connection.commit(); res.json({ success: true, message: 'Bidding re-opened successfully.' }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
apiRouter.get('/users/pending', authenticateToken, isAdmin, async (req, res, next) => { try { const [rows] = await dbPool.query(`SELECT temp_id, full_name, email, role, company_name, contact_number FROM pending_users ORDER BY temp_id DESC`); const data = rows.map(u => ({...u, role: u.role === 'Vendor' ? 'Trucker' : 'Shipper'})); res.json({ success: true, data }); } catch (error) { next(error); }});
apiRouter.post('/users/approve', authenticateToken, isAdmin, async (req, res, next) => { try { const { temp_id } = req.body; const [[pendingUser]] = await dbPool.query('SELECT * FROM pending_users WHERE temp_id = ?', [temp_id]); if (!pendingUser) return res.status(404).json({ success: false, message: 'User not found' }); await dbPool.query('INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)', [pendingUser.full_name, pendingUser.email, pendingUser.password, pendingUser.role, pendingUser.company_name, pendingUser.contact_number, pendingUser.gstin]); await dbPool.query('DELETE FROM pending_users WHERE temp_id = ?', [temp_id]); res.json({ success: true, message: 'User approved!' }); } catch (error) { next(error); }});
apiRouter.delete('/pending-users/:id', authenticateToken, isAdmin, async (req, res, next) => { try { await dbPool.query('DELETE FROM pending_users WHERE temp_id = ?', [req.params.id]); res.json({ success: true, message: 'Pending user rejected.' }); } catch (error) { next(error); }});
apiRouter.get('/users', authenticateToken, isAdmin, async (req, res, next) => { try { const [rows] = await dbPool.query(`SELECT user_id, full_name, email, role, company_name, contact_number, gstin FROM users ORDER BY full_name`); const data = rows.map(u => ({...u, role: u.role === 'Vendor' ? 'Trucker' : (u.role === 'User' ? 'Shipper' : u.role)})); res.json({ success: true, data }); } catch (error) { next(error); }});
apiRouter.get('/users/truckers', authenticateToken, isAdmin, async (req, res, next) => { try { const [rows] = await dbPool.query(`SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1 ORDER BY full_name`); res.json({ success: true, data: rows }); } catch(e) { next(e) }});
apiRouter.post('/users', authenticateToken, isAdmin, async (req, res, next) => { try { const { full_name, email, password, role, company_name, contact_number, gstin } = req.body; const hashedPassword = await bcrypt.hash(password, 10); const dbRole = (role === 'Trucker') ? 'Vendor' : (role === 'Shipper' ? 'User' : role); await dbPool.query('INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)', [full_name, email, hashedPassword, dbRole, company_name, contact_number, gstin]); res.status(201).json({ success: true, message: 'User created successfully.' }); } catch (error) { if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' }); next(error); }});
apiRouter.put('/users/:id', authenticateToken, isAdmin, async (req, res, next) => { try { const { id } = req.params; const { full_name, email, role, company_name, contact_number, gstin, password } = req.body; const dbRole = (role === 'Trucker') ? 'Vendor' : (role === 'Shipper' ? 'User' : role); let query = 'UPDATE users SET full_name=?, email=?, role=?, company_name=?, contact_number=?, gstin=?'; let params = [full_name, email, dbRole, company_name, contact_number, gstin]; if (password) { const hashedPassword = await bcrypt.hash(password, 10); query += ', password_hash=?'; params.push(hashedPassword); } query += ' WHERE user_id=?'; params.push(id); await dbPool.query(query, params); res.json({ success: true, message: 'User updated successfully.' }); } catch (error) { next(error); }});
apiRouter.delete('/users/:id', authenticateToken, isAdmin, async (req, res, next) => { try { await dbPool.query('DELETE FROM users WHERE user_id = ?', [req.params.id]); res.json({ success: true, message: 'User deleted successfully.' }); } catch (error) { next(error); }});
apiRouter.post('/master-data/:type', authenticateToken, isAdmin, async (req, res, next) => { try { const { type } = req.params; const { name } = req.body; const table = type === 'items' ? 'item_master' : 'truck_type_master'; const column = type === 'items' ? 'item_name' : 'truck_name'; await dbPool.query(`INSERT INTO ${table} (${column}) VALUES (?)`, [name]); res.status(201).json({ success: true, message: `${type.slice(0, -1)} added` }); } catch (e) { next(e) } });
apiRouter.put('/master-data/:type/:id', authenticateToken, isAdmin, async (req, res, next) => { try { const { type, id } = req.params; const { name, is_active } = req.body; const table = type === 'items' ? 'item_master' : 'truck_type_master'; const nameColumn = type === 'items' ? 'item_name' : 'truck_name'; const idColumn = type === 'items' ? 'item_id' : 'truck_type_id'; await dbPool.query(`UPDATE ${table} SET ${nameColumn}=?, is_active=? WHERE ${idColumn}=?`, [name, is_active, id]); res.json({ success: true, message: `${type.slice(0, -1)} updated` }); } catch (e) { next(e) } });
apiRouter.post('/master-data/:type/bulk-upload', authenticateToken, isAdmin, upload.single('bulkFile'), async (req, res, next) => { if (!req.file) return res.status(400).json({ success: false, message: 'No Excel file provided.' }); try { const { type } = req.params; const table = type === 'items' ? 'item_master' : 'truck_type_master'; const column = type === 'items' ? 'item_name' : 'truck_name'; const workbook = xlsx.read(req.file.buffer, { type: 'buffer' }); const jsonData = xlsx.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]]); const values = jsonData.map(row => [row.Name]); if (values.length > 0) { await dbPool.query(`INSERT INTO ${table} (${column}) VALUES ?`, [values]); } res.json({ success: true, message: 'Bulk upload successful.' }); } catch (e) { next(e); } });
apiRouter.get('/conversations', authenticateToken, async (req, res, next) => {
    try {
        const myId = req.user.userId;
        let query = 'SELECT user_id, full_name, role FROM users WHERE user_id != ? AND is_active = 1';
        const params = [myId];

        if (req.user.role === 'Trucker') {
            query += " AND role IN ('Admin', 'Super Admin', 'User')";
        }

        const [users] = await dbPool.query(query, params);
        if (users.length === 0) return res.json({ success: true, data: [] });

        const userMap = new Map(users.map(u => [u.user_id, { user_id: u.user_id, full_name: u.full_name, role: u.role === 'Vendor' ? 'Trucker' : (u.role === 'User' ? 'Shipper' : u.role), last_message: null, last_message_timestamp: null, last_message_status: null, last_message_sender: null, unread_count: 0 }]));
        const otherUserIds = Array.from(userMap.keys());

        if (otherUserIds.length > 0) {
            const lastMessagesQuery = `SELECT * FROM messages m WHERE m.message_id IN ( SELECT MAX(message_id) FROM messages WHERE (sender_id = ? AND recipient_id IN (?)) OR (recipient_id = ? AND sender_id IN (?)) GROUP BY LEAST(sender_id, recipient_id), GREATEST(sender_id, recipient_id) )`;
            const [lastMessages] = await dbPool.query(lastMessagesQuery, [myId, otherUserIds, myId, otherUserIds]);
            const unreadQuery = `SELECT sender_id, COUNT(*) as count FROM messages WHERE recipient_id = ? AND status != 'read' GROUP BY sender_id`;
            const [unreadCounts] = await dbPool.query(unreadQuery, [myId]);

            lastMessages.forEach(msg => {
                const otherUserId = msg.sender_id == myId ? msg.recipient_id : msg.sender_id;
                if (userMap.has(otherUserId)) {
                    const user = userMap.get(otherUserId);
                    user.last_message = msg.message_body;
                    user.last_message_timestamp = msg.timestamp;
                    user.last_message_status = msg.status;
                    user.last_message_sender = msg.sender_id;
                }
            });
            unreadCounts.forEach(uc => {
                if (userMap.has(uc.sender_id)) {
                    userMap.get(uc.sender_id).unread_count = uc.count;
                }
            });
        }

        const sortedUsers = Array.from(userMap.values()).sort((a, b) => (new Date(b.last_message_timestamp) || 0) - (new Date(a.last_message_timestamp) || 0));
        res.json({ success: true, data: sortedUsers });
    } catch (e) {
        next(e);
    }
});
apiRouter.get('/messages/:otherUserId', authenticateToken, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { otherUserId } = req.params; const myId = req.user.userId; await connection.beginTransaction(); const [messages] = await connection.query('SELECT * FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) ORDER BY timestamp ASC', [myId, otherUserId, otherUserId, myId]); await connection.query("UPDATE messages SET status = 'read' WHERE recipient_id = ? AND sender_id = ? AND status != 'read'", [myId, otherUserId]); await connection.commit(); res.json({ success: true, data: messages }); } catch(e) { if(connection) await connection.rollback(); next(e); } finally { if(connection) connection.release(); }});
apiRouter.get('/sidebar-counts', authenticateToken, async (req, res, next) => { try { let counts = { unreadMessages: 0, pendingLoads: 0, pendingUsers: 0 }; const [[msgCount]] = await dbPool.query("SELECT COUNT(*) as count FROM messages WHERE recipient_id = ? AND status != 'read'", [req.user.userId]); counts.unreadMessages = msgCount.count; if(req.user.role === 'Admin' || req.user.role === 'Super Admin') { const [[pendingUsers]] = await dbPool.query("SELECT COUNT(*) as count FROM pending_users"); counts.pendingUsers = pendingUsers.count; const [[pendingLoads]] = await dbPool.query("SELECT COUNT(*) as count FROM truck_loads WHERE status = 'Pending Approval'"); counts.pendingLoads = pendingLoads.count; } res.json({ success: true, data: counts }); } catch(e){next(e)} });
apiRouter.post('/loads/bulk-upload', authenticateToken, isAdmin, upload.single('bulkFile'), async (req, res, next) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'No Excel file provided.' });
    }
    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        const jsonData = xlsx.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]], { cellDates: true });
        const totalRows = jsonData.length;
        const [result] = await dbPool.query(
            "INSERT INTO bulk_upload_history (file_name, uploaded_by_user_id, status, started_at, total_rows) VALUES (?, ?, 'PROCESSING', NOW(), ?)",
            [req.file.originalname, req.user.userId, totalRows]
        );
        const uploadId = result.insertId;
        res.status(202).json({ success: true, message: 'File received. Processing has started. Check history for status updates.' });
        processBulkUpload(uploadId, jsonData, req.user.userId);
    } catch (error) {
        console.error("Error in bulk upload initial handling:", error);
        next(error);
    }
});
apiRouter.get('/admin/bulk-upload-history', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [historyRows] = await dbPool.query(`
            SELECT b.*, u.full_name as uploaded_by_name 
            FROM bulk_upload_history b
            LEFT JOIN users u ON b.uploaded_by_user_id = u.user_id
            ORDER BY b.started_at DESC
            LIMIT 50
        `);
        res.json({ success: true, data: historyRows });
    } catch (error) {
        next(error);
    }
});
apiRouter.get('/admin/download-error-file/:uploadId', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { uploadId } = req.params;
        const [[history]] = await dbPool.query("SELECT error_file_path, file_name FROM bulk_upload_history WHERE upload_id = ?", [uploadId]);
        if (!history || !history.error_file_path) {
            return res.status(404).send('Error file not found.');
        }
        const fileName = path.basename(history.error_file_path);
        const filePath = path.join(ERROR_REPORTS_DIR, fileName);
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        const originalFileName = history.file_name.replace(/\.xlsx$/i, '');
        const downloadFileName = `error_${originalFileName}.xlsx`;
        res.download(filePath, downloadFileName, (err) => {
            if (err) {
                 console.error("Error downloading file:", err);
                 if (!res.headersSent) {
                    res.status(500).send('Could not download the file.');
                 }
            }
        });
    } catch(e) {
        next(e);
    }
});


app.use('/error_reports', authenticateToken, isAdmin, express.static(ERROR_REPORTS_DIR));
app.use('/api', apiRouter);

// Global Error Handler
app.use((err, req, res, next) => {
    console.error("====== GLOBAL ERROR HANDLER CAUGHT AN ERROR ======");
    console.error("ROUTE: ", req.method, req.originalUrl);
    console.error(err);
    res.status(500).send({
        success: false,
        message: err.message || 'Something went wrong!'
    });
});

module.exports = app;

