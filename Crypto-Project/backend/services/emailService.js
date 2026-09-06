const nodemailer = require('nodemailer');

/**
 * Creates nodemailer transport if SMTP env settings are present
 */
const getTransporter = () => {
    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
        return nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT || '587', 10),
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
        });
    }
    return null;
};

/**
 * Sends an OTP email to the user. Fallbacks to server console output if SMTP credentials are missing.
 * @param {string} email 
 * @param {string} otp 
 * @param {string} purpose - 'login' or 'register'
 */
const sendOtpEmail = async (email, otp, purpose = 'login') => {
    const transporter = getTransporter();
    const actionName = purpose === 'register' ? 'Account Registration' : 'Account Login';
    const fromAddress = process.env.EMAIL_FROM || '"GameVault Security" <no-reply@gamevault.com>';

    const htmlContent = `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0c0f1d; color: #e2e8f0; padding: 40px 20px; border-radius: 12px; max-width: 520px; margin: 0 auto; border: 1px solid #1e293b;">
            <div style="text-align: center; margin-bottom: 25px;">
                <h1 style="color: #6366f1; margin: 0; font-size: 28px; letter-spacing: 1px; font-weight: 800;">🔐 GameVault Security</h1>
                <p style="color: #94a3b8; font-size: 14px; margin-top: 5px;">One-Time Password Verification</p>
            </div>
            <div style="background-color: #151c2e; padding: 25px; border-radius: 10px; border: 1px solid #2e3856;">
                <p style="margin-top: 0; color: #cbd5e1; font-size: 15px;">Hello,</p>
                <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
                    You have requested a verification code for <strong>${actionName}</strong>. Please use the following 6-digit OTP code to complete your request:
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <span style="display: inline-block; background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); color: #ffffff; font-size: 32px; font-weight: 800; letter-spacing: 10px; padding: 15px 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);">
                        ${otp}
                    </span>
                </div>
                <p style="color: #94a3b8; font-size: 13px; line-height: 1.5; margin-bottom: 0;">
                    ⏰ <strong>Note:</strong> This code is valid for <strong>5 minutes</strong>. Do not share this OTP with anyone for your security.
                </p>
            </div>
            <div style="text-align: center; margin-top: 25px; color: #64748b; font-size: 12px;">
                <p style="margin: 0;">If you did not request this code, please ignore this email.</p>
                <p style="margin: 5px 0 0 0;">&copy; ${new Date().getFullYear()} GameVault. All rights reserved.</p>
            </div>
        </div>
    `;

    // Print to console regardless for instant developer verification
    console.log('\n=============================================================');
    console.log(` 🔑 [OTP MAIL SERVICE] Code for ${email} (${purpose}): [ ${otp} ]`);
    console.log('=============================================================\n');

    if (transporter) {
        try {
            await transporter.sendMail({
                from: fromAddress,
                to: email,
                subject: `[GameVault] Your OTP Code: ${otp}`,
                html: htmlContent,
            });
            console.log(`[OTP MAIL SERVICE] Successfully dispatched email to ${email}`);
            return true;
        } catch (err) {
            console.error(`[OTP MAIL SERVICE ERROR] Failed to send email via SMTP:`, err.message);
            return false;
        }
    } else {
        console.log(`[OTP MAIL SERVICE INFO] SMTP credentials not set in .env. Falling back to console OTP display.`);
        return true;
    }
};

module.exports = {
    sendOtpEmail
};
