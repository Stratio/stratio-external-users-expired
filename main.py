#!/bin/python3

# IMPORTS
import argparse
import calendar
import configparser
from ldap3 import Server, Connection, ALL, SIMPLE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import LDAPCursorError
import logging
import time
import smtplib

# VARS
CONFIG_FILE_PATH = "./config.ini"
DEFAULT_LOGGING = "debug"


def load_config(config_file_path):
    logging.info("Read config file {}".format(config_file_path))
    config = configparser.ConfigParser()
    config.read(config_file_path)

    return config


def get_ldap_users(config, days_expire):
    if config['LDAP']['server'].count(':') != 1:
        logging.error('LDAP Server bad format: <hostname/IP>:port')
        exit(-1)
    logging.info('Connecting to LDAP server {}'.format(config['LDAP']['server'].split(':')[0]))
    logging.info('Connecting to LDAP port {}'.format(config['LDAP']['server'].split(':')[1]))

    server = Server(config['LDAP']['server'].split(':')[0],
                    port=int(config['LDAP']['server'].split(':')[1]),
                    get_info=ALL)

    logging.info('Connecting to LDAP with username {}'.format(config['LDAP']['user_name']))
    logging.info('Connecting to LDAP with password ****')
    conn = Connection(server,
                      user=config['LDAP']['user_name'],
                      password=config['LDAP']['password'],
                      authentication=SIMPLE,
                      auto_bind="NO_TLS")

    logging.info('Search in LDAP with base {}'.format(config['LDAP']['base_search']))
    logging.info('Search in LDAP with filter {}'.format(config['LDAP']['filter']))
    conn.search(config['LDAP']['base_search'],
                config['LDAP']['filter'],
                attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])

    users = []
    managers = []
    now = calendar.timegm(time.gmtime())
    epoch_expire = days_expire * 24 * 60 * 60
    for user in conn.entries:
        service = ""
        try:
            if int(str(user.shadowExpire)) - now < epoch_expire:
                for description in user.description:

                    if "Responsable" not in description:
                        service = str(description)

                    if "Responsable" in description:
                        manager = str(description).split(',')[0].split(': ')[1].strip()
                        if manager not in managers:
                            managers.append(manager)
                        users.append({"user": str(user.uid),
                                      "mail": str(user.mail),
                                      "expire": str(user.shadowExpire),
                                      "manager": str(manager),
                                      "service": str(service),
                                      "jira": str(description).split(',')[1].split(': ')[1].strip()})

        except LDAPCursorError:
            logging.error("Cant get LDAP Users")
            exit(-1)
    return managers, users


def send_mails(config, managers, users, days):
    logging.info("Prepare to send emails to managers")
    for manager in managers:
        logging.debug("Sending mail to {}@stratio.com".format(manager))
        mail_headers = """From: <sistemas@stratio.com>
To: To Person <hbermudez@stratio.com>
MIME-Version: 1.0
Content-type: text/html
Subject: External user access expiration
"""

        mail_body = """
Hi: 
<br><br>
This is friendly reminder: <b>next users will lose their access in the next {} days</b>:
<br>
<table>
  <tr>
    <th>User</th>
    <th>Mail</th>
    <th>Expire Date</th>
    <th>Service</th>
    <th>Jira</th>
  </tr>
""".format(days)
        mail_users = ""
        for user in users:
            if user["manager"] == manager:
                mail_users = mail_users + """  <tr>
    <td>{}</td>
    <td>{}</td>
    <td>{}</td>
    <td>{}</td>
    <td>https://stratio.atlassian.net/browse/{}</td>
  </tr>
""".format(user["user"],
           user["mail"],
           time.strftime('%Y-%m-%d', time.localtime(int(user["expire"]))),
           user["service"],
           user["jira"])

        mail_tail = """</table>
<br>
You must notify the <b>team responsible</b> for the service so that the user does not lose access <b>before its expiration date</b>.
<br><br>
Thanks for your time
"""
        mail_text = mail_headers + mail_body + mail_users + mail_tail

        logging.debug("Sending mail:")
        logging.debug('\t\t'.join(mail_text.splitlines(True)))
        try:
            smtp_obj = smtplib.SMTP(str(config['MAIL']['host']),
                                    int(str(config['MAIL']['port'])))
            smtp_obj.connect(str(config['MAIL']['host']),
                             int(str(config['MAIL']['port'])))
            smtp_obj.ehlo()
            smtp_obj.starttls()
            smtp_obj.ehlo()
            smtp_obj.login(user=str(config['MAIL']['user']),
                           password=str(config['MAIL']['password']))

            # smtp_obj.sendmail("sistemas@stratio.com",
            #                   "{}@stratio.com".format(manager),
            #                   mail)
            smtp_obj.sendmail("sistemas@stratio.com",
                              "hbermudez@stratio.com",
                              mail_text)
            smtp_obj.quit()

        except smtplib.SMTPException as e:
            logging.error("Unable to send email to {}: {}".format(manager, e))
        exit(0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("days",
                        type=int,
                        help="Days to calculate user expire access. Mandatory")
    parser.add_argument("-c", "--conf",
                        dest="config_file_path",
                        default=CONFIG_FILE_PATH,
                        help="Path to the config file in .ini format. Default: config.ini")
    parser.add_argument("-l", "--log",
                        dest="log_level",
                        default=DEFAULT_LOGGING,
                        help="Log level for the application [debug, info, warn, error]. Default: info")
    args = parser.parse_args()

    if args.log_level in ("debug", "DEBUG"):
        logging_level = logging.DEBUG
    elif args.log_level in ("info", "INFO"):
        logging_level = logging.INFO
    elif args.log_level in ("warn", "WARN", "warning", "WARNING"):
        logging_level = logging.WARN
    elif args.log_level in ("error", "ERROR"):
        logging_level = logging.ERROR
    else:
        logging.warning("Bad logging level selected, using warn")
        logging_level = logging.WARN

    logging.basicConfig(encoding='utf-8', level=logging_level)
    if args.days <= 0:
        logging.error("Days must be a int > 0")
        exit(-1)
    config = load_config(args.config_file_path)
    managers, users = get_ldap_users(config, args.days)
    send_mails(config, managers, users, args.days)


# MAIN.
if __name__ == '__main__':
    main()
