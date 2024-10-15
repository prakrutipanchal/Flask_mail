
import os
import smtplib
from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'prakrutipanchal2005@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'prakrutipanchal2005@gmail.com'
mail = Mail(app)

def send_test_email():
    try:
        with app.app_context():
            msg = Message(subject="Helllo",
                          sender=app.config.get("MAIL_USERNAME"),
                          recipients=["prakrutipanchal2005@gmail.com"], 
                          body="This is a test email")
            mail.send(msg)
            print("Email sent successfully!")
    except smtplib.SMTPException as e:
        print(f"Failed to send email: {e}")

if __name__ == '__main__':
    send_test_email()
