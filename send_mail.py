import smtplib
import random
import os


class SendMail:
    def __init__(self, to_mail: str, name: str):
        self.from_mail = os.environ.get("EMAIL")
        self.password = os.environ.get("PASSWORD")
        self.to_mail = to_mail

        self.code = random.randint(100000, 999999)
        self.message = f"Subject: Account verfication code: {self.code}\n\n" \
                       f"Hi {name},\n" \
                       f"Thanks for signing up for the Minecraft treasure hunt. Before continuing we need to verify " \
                       f"your email address.\n\n" \
                       f"Verification Code: {self.code}"

    def verify(self):
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=self.from_mail,
                             password=self.password)
            connection.sendmail(
                from_addr=self.from_mail,
                to_addrs=self.to_mail,
                msg=self.message
            )

        return self.code
