import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# SMTP configuration
smtp_server = 'smtp.gmail.com'
smtp_port = 587
smtp_user = 'harshitapurwar07@gmail.com'
smtp_password = 'ynra oigu cige mhva'

# Create message
sender_email = smtp_user
receiver_email = 'harshitapurwar6307@gmail.com'
subject = 'Test Email'
body = 'This is a test email.'

msg = MIMEMultipart()
msg['From'] = sender_email
msg['To'] = receiver_email
msg['Subject'] = subject
msg.attach(MIMEText(body, 'plain'))

# Try to send the email
try:
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_user, smtp_password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    print('Email sent successfully!')
except Exception as e:
    print(f'Error sending email: {e}')
finally:
    server.quit()
