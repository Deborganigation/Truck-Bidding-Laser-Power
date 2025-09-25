const bcrypt = require('bcrypt');

const users = [
    { FullName: 'ReqBin Test Vendor', Email: 'vendor@reqbin.com', Password: 'Deb@2020', Role: 'Vendor', CompanyName: 'ReqBin Testing Inc.', ContactNumber: '', GSTIN: '' },
    { FullName: 'Debopriya', Email: 'protulchatterjee2020@gmail.com', Password: 'Deb@2020', Role: 'Admin', CompanyName: 'ReqBin Testing Inc.', ContactNumber: '', GSTIN: '' },
    { FullName: 'New Test Vendor', Email: 'newvendor@test.com', Password: 'password123', Role: 'Vendor', CompanyName: 'Test Company Inc.', ContactNumber: '', GSTIN: '' },
    { FullName: 'Samrat Dey', Email: 'samrat.dey@laserpowerinfra.com', Password: 'Deb@2020', Role: 'Vendor', CompanyName: '', ContactNumber: '', GSTIN: '' },
    { FullName: 'Dipankar shil', Email: 'laser.mis4@gmail.com', Password: 'Deb@2020', Role: 'Admin', CompanyName: 'Dipankar University', ContactNumber: '', GSTIN: '' },
    { FullName: 'ReqBin Vendor 2', Email: 'vendor2@reqbin.com', Password: 'password', Role: 'Vendor', CompanyName: 'ReqBin Corp 2', ContactNumber: '', GSTIN: '' },
    { FullName: 'ReqBin Test User', Email: 'test@reqbin.com', Password: 'password123', Role: 'User', CompanyName: '', ContactNumber: '', GSTIN: '' },
    { FullName: 'SAURABH MISHRA', Email: 'rishu8127232449@gmail.com', Password: 'Vendor@123', Role: 'Vendor', CompanyName: 'Saurabh Dairy Pvt Ltd', ContactNumber: '', GSTIN: '' },
    { FullName: 'Vikash Kumar', Email: 'Laser.mis8@Gmail.com', Password: 'Deb@2020', Role: 'User', CompanyName: '', ContactNumber: '9643455301', GSTIN: '' }
];

async function generateSeedSQL() {
    console.log("TRUNCATE TABLE users; -- Yeh pehle purane saare users ko delete kar dega");

    for (const user of users) {
        const hashedPassword = await bcrypt.hash(user.Password, 10);
        // SQL Injection se bachne ke liye values ko aese format kiya gaya hai
        const fullName = user.FullName.replace(/'/g, "''");
        const companyName = user.CompanyName.replace(/'/g, "''");

        const sql = `INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin) VALUES ('${fullName}', '${user.Email}', '${hashedPassword}', '${user.Role}', '${companyName}', '${user.ContactNumber}', '${user.GSTIN}');`;
        console.log(sql);
    }
}

generateSeedSQL();