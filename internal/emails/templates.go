package emails

import (
	"fmt"
	"time"
	"log"
	"os"
	"github.com/resend/resend-go/v2"
)

func CreateOTPEmailHTML(otp string) string {
    return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SwiftVault - Verification Code</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
    <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
        
        <div style="background: linear-gradient(135deg, #3b82f6 0%%, #8b5cf6 50%%, #3b82f6 100%%); padding: 40px 30px; text-align: center;">
            <div style="display: inline-flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.1); padding: 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.2); margin-bottom: 20px;">
                <div style="width: 24px; height: 24px; background: #60a5fa; border-radius: 4px; position: relative;">
                    <div style="position: absolute; top: 50%%; left: 50%%; transform: translate(-50%%, -50%%); width: 12px; height: 12px; background: white; border-radius: 2px;"></div>
                </div>
            </div>
            <h1 style="margin: 0; color: white; font-size: 28px; font-weight: bold; background: linear-gradient(45deg, #60a5fa, #a78bfa, #60a5fa); background-clip: text; -webkit-background-clip: text; -webkit-text-fill-color: transparent;">SwiftVault</h1>
            <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.8); font-size: 14px; font-weight: 500;">Intelligent File Storage & Sharing</p>
        </div>
        
        <div style="padding: 40px 30px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="margin: 0 0 10px 0; color: #1f2937; font-size: 24px; font-weight: bold;">Verify Your Email</h2>
                <p style="margin: 0; color: #6b7280; font-size: 16px;">Enter this verification code to complete your registration</p>
            </div>
            
            <div style="text-align: center; margin: 40px 0;">
                <div style="display: inline-block; background: linear-gradient(135deg, #f8fafc 0%%, #f1f5f9 100%%); border: 2px solid #e2e8f0; border-radius: 16px; padding: 30px 40px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0 0 10px 0; color: #64748b; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Verification Code</p>
                    <div style="font-size: 32px; font-weight: bold; color: #1e293b; letter-spacing: 8px; font-family: 'Courier New', monospace; background: linear-gradient(135deg, #3b82f6, #8b5cf6); background-clip: text; -webkit-background-clip: text; -webkit-text-fill-color: transparent;">%s</div>
                </div>
            </div>
            
            <div style="background: linear-gradient(135deg, #dbeafe 0%%, #e0e7ff 100%%); border-left: 4px solid #3b82f6; border-radius: 8px; padding: 20px; margin: 30px 0;">
                <div style="display: flex; align-items: flex-start;">
                    <div style="flex-shrink: 0; width: 20px; height: 20px; background: #3b82f6; border-radius: 50%%; margin-right: 12px; margin-top: 2px;">
                        <div style="width: 8px; height: 8px; background: white; border-radius: 50%%; margin: 6px auto;"></div>
                    </div>
                    <div>
                        <h3 style="margin: 0 0 8px 0; color: #1e40af; font-size: 16px; font-weight: 600;">Important Security Information</h3>
                        <ul style="margin: 0; padding-left: 0; color: #1e40af; font-size: 14px; line-height: 1.6;">
                            <li style="list-style: none; margin-bottom: 6px;">• This code expires in <strong>10 minutes</strong></li>
                            <li style="list-style: none; margin-bottom: 6px;">• Use it only on the SwiftVault registration page</li>
                            <li style="list-style: none;">• Never share this code with anyone</li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div style="text-align: center; padding-top: 30px; border-top: 1px solid #e5e7eb; margin-top: 40px;">
                <p style="margin: 0; color: #6b7280; font-size: 14px;">Didn't request this verification code?</p>
                <p style="margin: 8px 0 0 0; color: #6b7280; font-size: 14px;">You can safely ignore this email if you didn't sign up for SwiftVault.</p>
            </div>
        </div>
        
        <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
            <div style="margin-bottom: 20px;">
                <div style="display: inline-flex; align-items: center; justify-content: center; margin-bottom: 12px;">
                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 4px; margin-right: 8px;"></div>
                    <span style="color: #374151; font-size: 16px; font-weight: bold;">SwiftVault</span>
                </div>
                <p style="margin: 0; color: #6b7280; font-size: 14px; font-weight: 500;">Intelligent File Storage & Sharing Platform</p>
            </div>
            
            <div style="border-top: 1px solid #e5e7eb; padding-top: 20px;">
                <p style="margin: 0; color: #9ca3af; font-size: 12px;">
                    © 2025 SwiftVault - Built for BalkanID Challenge<br>
                    This email was sent regarding your SwiftVault account registration.
                </p>
            </div>
        </div>
    </div>
</body>
</html>`, otp)
}

func CreateResetOTPHTML(otp string) string {
    return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SwiftVault - Password Reset Code</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
    <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
        
        <div style="background: linear-gradient(135deg, #3b82f6 0%%, #8b5cf6 50%%, #3b82f6 100%%); padding: 40px 30px; text-align: center;">
            <div style="display: inline-flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.1); padding: 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.2); margin-bottom: 20px;">
                <div style="width: 24px; height: 24px; background: #60a5fa; border-radius: 4px; position: relative;">
                    <div style="position: absolute; top: 50%%; left: 50%%; transform: translate(-50%%, -50%%); width: 12px; height: 12px; background: white; border-radius: 2px;"></div>
                </div>
            </div>
            <h1 style="margin: 0; color: white; font-size: 28px; font-weight: bold; background: linear-gradient(45deg, #60a5fa, #a78bfa, #60a5fa); background-clip: text; -webkit-background-clip: text; -webkit-text-fill-color: transparent;">SwiftVault</h1>
            <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.8); font-size: 14px; font-weight: 500;">Intelligent File Storage & Sharing</p>
        </div>
        
        <div style="padding: 40px 30px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="margin: 0 0 10px 0; color: #1f2937; font-size: 24px; font-weight: bold;">Password Reset Verification</h2>
                <p style="margin: 0; color: #6b7280; font-size: 16px;">Use the code below to reset your password.</p>
            </div>
            
            <div style="text-align: center; margin: 40px 0;">
                <div style="display: inline-block; background: linear-gradient(135deg, #f8fafc 0%%, #f1f5f9 100%%); border: 2px solid #e2e8f0; border-radius: 16px; padding: 30px 40px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);">
                    <p style="margin: 0 0 10px 0; color: #64748b; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Password Reset Code</p>
                    <div style="font-size: 32px; font-weight: bold; color: #1e293b; letter-spacing: 8px; font-family: 'Courier New', monospace; background: linear-gradient(135deg, #3b82f6, #8b5cf6); background-clip: text; -webkit-background-clip: text; -webkit-text-fill-color: transparent;">%s</div>
                </div>
            </div>
            
            <div style="background: linear-gradient(135deg, #dbeafe 0%%, #e0e7ff 100%%); border-left: 4px solid #3b82f6; border-radius: 8px; padding: 20px; margin: 30px 0;">
                <div style="display: flex; align-items: flex-start;">
                    <div style="flex-shrink: 0; width: 20px; height: 20px; background: #3b82f6; border-radius: 50%%; margin-right: 12px; margin-top: 2px;">
                        <div style="width: 8px; height: 8px; background: white; border-radius: 50%%; margin: 6px auto;"></div>
                    </div>
                    <div>
                        <h3 style="margin: 0 0 8px 0; color: #1e40af; font-size: 16px; font-weight: 600;">Important Security Information</h3>
                        <ul style="margin: 0; padding-left: 0; color: #1e40af; font-size: 14px; line-height: 1.6;">
                            <li style="list-style: none; margin-bottom: 6px;">• This code expires in <strong>10 minutes</strong></li>
                            <li style="list-style: none; margin-bottom: 6px;">• Use it only to reset your password on SwiftVault</li>
                            <li style="list-style: none;">• Never share this code with anyone</li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div style="text-align: center; padding-top: 30px; border-top: 1px solid #e5e7eb; margin-top: 40px;">
                <p style="margin: 0; color: #6b7280; font-size: 14px;">Didn't request a password reset?</p>
                <p style="margin: 8px 0 0 0; color: #6b7280; font-size: 14px;">You can safely ignore this email.</p>
            </div>
        </div>
        
        <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
            <div style="margin-bottom: 20px;">
                <div style="display: inline-flex; align-items: center; justify-content: center; margin-bottom: 12px;">
                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 4px; margin-right: 8px;"></div>
                    <span style="color: #374151; font-size: 16px; font-weight: bold;">SwiftVault</span>
                </div>
                <p style="margin: 0; color: #6b7280; font-size: 14px; font-weight: 500;">Intelligent File Storage & Sharing Platform</p>
            </div>
            
            <div style="border-top: 1px solid #e5e7eb; padding-top: 20px;">
                <p style="margin: 0; color: #9ca3af; font-size: 12px;">
                    © 2025 SwiftVault - Built for BalkanID Challenge<br>
                    This email was sent in response to a password reset request.
                </p>
            </div>
        </div>
    </div>
</body>
</html>`, otp)
}


func CreateWelcomeEmailHTML(userEmail string, creationDate string) string {
    return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to SwiftVault</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
    <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
        
        <div style="background: linear-gradient(135deg, #3b82f6 0%%, #8b5cf6 50%%, #3b82f6 100%%); padding: 40px 30px; text-align: center;">
            <div style="display: inline-flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.1); padding: 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.2); margin-bottom: 20px;">
                <div style="width: 24px; height: 24px; background: #60a5fa; border-radius: 4px; position: relative;">
                    <div style="position: absolute; top: 50%%; left: 50%%; transform: translate(-50%%, -50%%); width: 12px; height: 12px; background: white; border-radius: 2px;"></div>
                </div>
            </div>
            <h1 style="margin: 0; color: white; font-size: 32px; font-weight: bold;">Welcome to SwiftVault!</h1>
            <p style="margin: 12px 0 0 0; color: rgba(255,255,255,0.9); font-size: 16px; font-weight: 500;">Your intelligent file storage journey begins now</p>
        </div>
        
        <div style="padding: 40px 30px;">
            <div style="text-align: center; margin-bottom: 40px;">
                <h2 style="margin: 0 0 15px 0; color: #1f2937; font-size: 24px; font-weight: bold;">🎉 Registration Successful!</h2>
                <p style="margin: 0; color: #6b7280; font-size: 16px; line-height: 1.6;">Hi there! Welcome to SwiftVault - your secure, intelligent file storage platform. We're excited to have you on board!</p>
            </div>
            
            <div style="margin: 40px 0;">
                <h3 style="margin: 0 0 25px 0; color: #1f2937; font-size: 20px; font-weight: bold; text-align: center;">What you can do with SwiftVault:</h3>
                
                <div style="display: grid; gap: 20px;">
                    <div style="display: flex; align-items: flex-start; background: linear-gradient(135deg, #f0f9ff 0%%, #e0f2fe 100%%); border-left: 4px solid #0ea5e9; border-radius: 8px; padding: 20px;">
                        <div style="flex-shrink: 0; width: 40px; height: 40px; background: linear-gradient(135deg, #0ea5e9, #0284c7); border-radius: 8px; margin-right: 15px; display: flex; align-items: center; justify-content: center;">
                            <div style="width: 20px; height: 20px; background: white; border-radius: 4px;"></div>
                        </div>
                        <div>
                            <h4 style="margin: 0 0 8px 0; color: #0c4a6e; font-size: 16px; font-weight: 600;">Lightning-Fast Uploads</h4>
                            <p style="margin: 0; color: #0c4a6e; font-size: 14px; line-height: 1.5;">Upload multiple files with drag-and-drop. Our smart deduplication saves storage space automatically.</p>
                        </div>
                    </div>
                    
                    <div style="display: flex; align-items: flex-start; background: linear-gradient(135deg, #f0fdf4 0%%, #dcfce7 100%%); border-left: 4px solid #22c55e; border-radius: 8px; padding: 20px;">
                        <div style="flex-shrink: 0; width: 40px; height: 40px; background: linear-gradient(135deg, #22c55e, #16a34a); border-radius: 8px; margin-right: 15px; display: flex; align-items: center; justify-content: center;">
                            <div style="width: 20px; height: 20px; background: white; border-radius: 4px;"></div>
                        </div>
                        <div>
                            <h4 style="margin: 0 0 8px 0; color: #14532d; font-size: 16px; font-weight: 600;">Smart Sharing Controls</h4>
                            <p style="margin: 0; color: #14532d; font-size: 14px; line-height: 1.5;">Share files publicly or privately with granular controls. Track downloads and manage permissions easily.</p>
                        </div>
                    </div>
                    
                    <div style="display: flex; align-items: flex-start; background: linear-gradient(135deg, #fdf4ff 0%%, #f3e8ff 100%%); border-left: 4px solid #a855f7; border-radius: 8px; padding: 20px;">
                        <div style="flex-shrink: 0; width: 40px; height: 40px; background: linear-gradient(135deg, #a855f7, #9333ea); border-radius: 8px; margin-right: 15px; display: flex; align-items: center; justify-content: center;">
                            <div style="width: 20px; height: 20px; background: white; border-radius: 4px;"></div>
                        </div>
                        <div>
                            <h4 style="margin: 0 0 8px 0; color: #581c87; font-size: 16px; font-weight: 600;">Advanced Search</h4>
                            <p style="margin: 0; color: #581c87; font-size: 14px; line-height: 1.5;">Find any file instantly with our powerful search engine. Filter by type, size, date, and more.</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div style="text-align: center; background: linear-gradient(135deg, #dbeafe 0%%, #e0e7ff 100%%); border-radius: 16px; padding: 30px; margin: 40px 0;">
                <h3 style="margin: 0 0 15px 0; color: #1e40af; font-size: 20px; font-weight: bold;">Ready to get started?</h3>
                <p style="margin: 0 0 25px 0; color: #1e40af; font-size: 16px;">Upload your first file and experience the power of intelligent file management.</p>
                <a href="http://localhost:3000/dashboard" style="display: inline-block; background: linear-gradient(135deg, #3b82f6, #8b5cf6); color: white; text-decoration: none; padding: 15px 30px; border-radius: 10px; font-weight: 600; font-size: 16px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">Access Portal</a>
            </div>
            
            <div style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 12px; padding: 25px; margin: 30px 0;">
                <h4 style="margin: 0 0 15px 0; color: #374151; font-size: 18px; font-weight: 600;">Your Account Details</h4>
                <div style="color: #6b7280; font-size: 14px; line-height: 1.6;">
                    <p style="margin: 0 0 8px 0;"><strong>Email:</strong> %s</p>
                    <p style="margin: 0 0 8px 0;"><strong>Plan:</strong> Free (10MB storage limit)</p>
                    <p style="margin: 0 0 8px 0;"><strong>Storage Used:</strong> 0 MB of 10 MB</p>
                    <p style="margin: 0;"><strong>Account Created:</strong> %s</p>
                </div>
            </div>
            
            <div style="text-align: center; padding-top: 30px; border-top: 1px solid #e5e7eb; margin-top: 40px;">
                <p style="margin: 0 0 10px 0; color: #374151; font-size: 16px; font-weight: 600;">Need help getting started?</p>
                <p style="margin: 0; color: #6b7280; font-size: 14px;">SwiftVault is built for the BalkanID challenge, showcasing enterprise-grade file management capabilities.</p>
            </div>
        </div>
        
        <div style="background: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
            <div style="margin-bottom: 20px;">
                <div style="display: inline-flex; align-items: center; justify-content: center; margin-bottom: 12px;">
                    <div style="width: 20px; height: 20px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 4px; margin-right: 8px;"></div>
                    <span style="color: #374151; font-size: 16px; font-weight: bold;">SwiftVault</span>
                </div>
                <p style="margin: 0; color: #6b7280; font-size: 14px; font-weight: 500;">Intelligent File Storage & Sharing Platform</p>
            </div>
            
            <div style="border-top: 1px solid #e5e7eb; padding-top: 20px;">
                <p style="margin: 0; color: #9ca3af; font-size: 12px;">
                    © 2025 SwiftVault - Built for BalkanID Challenge<br>
                    Thank you for trying our intelligent file storage solution.
                </p>
            </div>
        </div>
    </div>
</body>
</html>`, userEmail, time.Now().Format("January 2, 2006"))
}

func ResetSuccessfulEmailHTML(toEmail, creationDate string) string {
    return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SwiftVault - Password Reset Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #f3f4f6;
            margin: 0;
            padding: 0;
            color: #333;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }
        .header {
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            padding: 40px 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            color: white;
            font-size: 28px;
            font-weight: bold;
        }
        .content {
            padding: 40px 30px;
            text-align: center;
        }
        .content h2 {
            margin: 0 0 10px 0;
            color: #1f2937;
            font-size: 24px;
            font-weight: bold;
        }
        .content p {
            margin: 0 0 20px 0;
            color: #6b7280;
            font-size: 16px;
            line-height: 1.5;
        }
        .cta-button {
            display: inline-block;
            background: #3b82f6;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: bold;
        }
        .footer {
            background: #f9fafb;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e5e7eb;
            color: #9ca3af;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SwiftVault</h1>
        </div>
        
        <div class="content">
            <h2>Password Successfully Reset</h2>
            <p>
                Hi there,
            </p>
            <p>
                This email is to confirm that the password for your SwiftVault account associated with <b>%s</b> was successfully changed on %s.
            </p>
            <a href="https://swiftvault.versioncv.com/login" class="cta-button">
                Log In to Your Account
            </a>
            <p style="margin-top: 30px; color: #6b7280; font-size: 14px;">
                If you did not reset your password, please contact our support team immediately.
            </p>
        </div>
        
        <div class="footer">
            © %s SwiftVault. All rights reserved.<br>
            This is an automated email. Please do not reply.
        </div>
    </div>
</body>
</html>`, toEmail, creationDate, time.Now().Format("2006"))
}

// Email sending functions
func SendVerificationEmail(toEmail, otp string) error {
	fromEmail := os.Getenv("RESEND_FROM_EMAIL")
	
	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("SwiftVault Security <%s>", fromEmail),
		To:      []string{toEmail},
		Subject: "🔐 SwiftVault - Your Verification Code",
		Html:    CreateOTPEmailHTML(otp),
	}
	
	resendClient := resend.NewClient(os.Getenv("RESEND_API_KEY"))
	_, err := resendClient.Emails.Send(params)
	if err != nil {
		log.Printf("Failed to send OTP email: %v", err)
		return err
	}
	
	return nil
}

func SendResetEmail(toEmail, otp string) error {
	fromEmail := os.Getenv("RESEND_FROM_EMAIL")	
	params := &resend.SendEmailRequest{
		From: fmt.Sprintf("SwiftVault Security <%s>", fromEmail),
		To:    []string{toEmail},
		Subject: "🔑 SwiftVault - Password Reset Verification Code",
		Html:   CreateResetOTPHTML(otp),
	}
	
	resendClient := resend.NewClient(os.Getenv("RESEND_API_KEY"))
	_, err := resendClient.Emails.Send(params)
	if err != nil {
		log.Printf("Failed to send password reset email: %v", err)
		return err
	}
	
	return nil
}

func SendWelcomeEmail(toEmail string) error {
	fromEmail := os.Getenv("RESEND_FROM_EMAIL")
	 creationDate := time.Now().Format("January 2, 2006")
	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("SwiftVault Team <%s>", fromEmail),
		To:      []string{toEmail},
		Subject: "🎉 Welcome to SwiftVault - Your Account is Ready!",
		Html:    CreateWelcomeEmailHTML(toEmail,creationDate),
	}
	
	resendClient := resend.NewClient(os.Getenv("RESEND_API_KEY"))
	_, err := resendClient.Emails.Send(params)
	if err != nil {
		log.Printf("Failed to send welcome email: %v", err)
		return err
	}
	
	return nil
}

func SendResetSuccessfulEmail(toEmail string) error {
	fromEmail := os.Getenv("RESEND_FROM_EMAIL")
	creationDate := time.Now().Format("January 2, 2006")
	
	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("SwiftVault Security <%s>", fromEmail),
		To:      []string{toEmail},
		Subject: "✅ SwiftVault - Your password has been reset successfully!",
		Html:    ResetSuccessfulEmailHTML(toEmail, creationDate),
	}
	
	resendClient := resend.NewClient(os.Getenv("RESEND_API_KEY"))
	_, err := resendClient.Emails.Send(params)
	if err != nil {
		log.Printf("Failed to send password reset successful email: %v", err)
		return err
	}
	
	return nil
}