#!/bin/python3

# IMPORTS
import argparse
import calendar
import configparser
from ldap3 import Server, Connection, ALL, SIMPLE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
import logging
import time
import smtplib

# VARS
CONFIG_FILE_PATH = "./config.ini"
DEFAULT_LOGGING = "debug"
ADMINISTRATORS = "sysinternal"


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
    users_delete = []
    managers_delete = []
    now = calendar.timegm(time.gmtime())
    if days_expire is None:
        days_expire = 0
    epoch_expire = days_expire * 24 * 60 * 60
    for user in conn.entries:
        if int(str(user.shadowExpire)) < now:
            info = [s for s in user.description if s.__contains__("Responsable")]
            manager = str(info[0]).split(',')[0].split(': ')[1].strip()
            if manager not in managers_delete:
                managers_delete.append(manager)
            service = [s for s in user.description if not s.__contains__("Responsable")]
            users_delete.append({"user": str(user.uid),
                                 "mail": str(user.mail),
                                 "expire": str(user.shadowExpire),
                                 "manager": str(manager),
                                 "service": str(service[0]),
                                 "jira": str(info).split(',')[1].split(': ')[1].strip()})

        elif int(str(user.shadowExpire)) - now < epoch_expire:
            info = [s for s in user.description if s.__contains__("Responsable")]
            manager = str(info[0]).split(',')[0].split(': ')[1].strip()
            if manager not in managers:
                managers.append(manager)
            service = [s for s in user.description if not s.__contains__("Responsable")]
            users.append({"user": str(user.uid),
                          "mail": str(user.mail),
                          "expire": str(user.shadowExpire),
                          "manager": str(manager),
                          "service": str(service[0]),
                          "jira": str(info).split(',')[1].split(': ')[1].strip()})

    return managers, users, managers_delete, users_delete


def delete_ldap_users(config, users, dry_run):
    if not dry_run:
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
        for user in users:
            logging.info('Delete user in LDAP: {}'.format(user['user']))

            conn.search(config['LDAP']['base_search'],
                        "(uid={})".format(user["user"]),
                        attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])

            user_dn = str(conn.entries[0]).partition('\n')[0].split(" - ")[0].split(": ")[1]
            logging.info('Delete user in LDAP with DN: {}'.format(user_dn))
            conn.delete(user_dn)
    else:
        logging.info("Param --dry-run detected, no user was deleted")


def send_mail_delete(config, managers, users, dry_run):
    logging.info("Prepare to send emails to managers")
    for manager in managers:
        mail_headers = """From: <sistemas@stratio.com>
To: To Person <{}@stratio.com>
MIME-Version: 1.0
Content-type: text/html
Subject: Remove external user access
""".format(manager)
        
        mail_body = """
Hi: 
<br><br>
Next access users were removed from their services associated:
<br>
<table>
  <tr>
    <th>User</th>
    <th>Mail</th>
    <th>Expire Date</th>
    <th>Service</th>
    <th>Jira</th>
  </tr>
"""
        mail_users = ""
        for user in users:
            if user["manager"] == manager:
                mail_users = mail_users + """  <tr>
    <td>{}</td>
    <td>{}</td>
    <td>{}</td>
    <td>{}</td>
""".format(user["user"],
           user["mail"],
           time.strftime('%d-%m-%Y', time.localtime(int(user["expire"]))),
           user["service"])

                if "??" in user["jira"]:
                    mail_users = mail_users +"""    <td>???</td>
  </tr>
"""
                else:
                    mail_users = mail_users + """    <td>https://stratio.atlassian.net/browse/{}</td>
  </tr>
""".format(user["jira"])

        mail_tail = """</table>
<br><br>
Thanks for your time
"""
        mail_text = mail_headers + mail_body + mail_users + mail_tail

        logging.debug("Sending mail:")
        logging.debug('\t\t'.join(mail_text.splitlines(True)))
        if not dry_run:
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

                smtp_obj.sendmail("sistemas@stratio.com",
                                  "{}@stratio.com".format(manager),
                                  mail_text)
                smtp_obj.quit()

            except smtplib.SMTPException as e:
                logging.error("Unable to send email to {}: {}".format(manager, e))
        else:
            logging.info("Param --dry-run detected, mail didn't send")

    logging.info("Prepare to send emails to administrators")
    mail_headers = """From: <sistemas@stratio.com>
To: To Person <{}@stratio.com>
MIME-Version: 1.0
Content-type: text/html
Subject: Remove external user access
""".format(ADMINISTRATORS)
        
    mail_body = """
Hi: 
<br><br>
Next access users were removed from their services associated:
<br>
<table>
  <tr>
    <th>User</th>
    <th>Mail</th>
    <th>Expire Date</th>
    <th>Service</th>
    <th>Jira</th>
  </tr>
"""
    mail_users = ""
    for user in users:
        mail_users = mail_users + """  <tr>
    <td>{}</td>
    <td>{}</td>
    <td>{}</td>
    <td>{}</td>
""".format(user["user"],
           user["mail"],
           time.strftime('%d-%m-%Y', time.localtime(int(user["expire"]))),
           user["service"])

        if "??" in user["jira"]:
            mail_users = mail_users +"""    <td>???</td>
  </tr>
"""
        else:
            mail_users = mail_users + """    <td>https://stratio.atlassian.net/browse/{}</td>
  </tr>
""".format(user["jira"])

        mail_tail = """</table>
<br><br>
Thanks for your time
"""
        mail_text = mail_headers + mail_body + mail_users + mail_tail

        logging.debug("Sending mail:")
        logging.debug('\t\t'.join(mail_text.splitlines(True)))
        if not dry_run:
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

                smtp_obj.sendmail("sistemas@stratio.com",
                                  "{}@stratio.com".format(ADMINISTRATORS),
                                  mail_text)
                smtp_obj.quit()

            except smtplib.SMTPException as e:
                logging.error("Unable to send email to {}: {}".format(ADMINISTRATORS, e))
        else:
            logging.info("Param --dry-run detected, mail didn't send")


def send_mails(config, managers, users, days, dry_run):
    logging.info("Prepare to send emails to managers")
    for manager in managers:
        logging.debug("Sending mail to {}@stratio.com".format(manager))
        mail_headers = """From: <sistemas@stratio.com>
To: To Person <{}@stratio.com>
MIME-Version: 1.0
Content-type: text/html
Subject: External user access expiration
""".format(manager)

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
""".format(user["user"],
           user["mail"],
           time.strftime('%d-%m-%Y', time.localtime(int(user["expire"]))),
           user["service"])

                if "??" in user["jira"]:
                    mail_users = mail_users +"""    <td>???</td>
  </tr>
"""
                else:
                    mail_users = mail_users + """    <td>https://stratio.atlassian.net/browse/{}</td>
  </tr>
""".format(user["jira"])

        mail_tail = """</table>
<br>
You must notify the <b>team responsible</b> for the service so that the user does not lose access <b>before its expiration date</b>.
<br><br>
Thanks for your time
"""
        mail_text = mail_headers + mail_body + mail_users + mail_tail

        logging.debug("Sending mail:")
        logging.debug('\t\t'.join(mail_text.splitlines(True)))
        if not dry_run:
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

                smtp_obj.sendmail("sistemas@stratio.com",
                                  "{}@stratio.com".format(manager),
                                  mail_text)
                smtp_obj.quit()

            except smtplib.SMTPException as e:
                logging.error("Unable to send email to {}: {}".format(manager, e))
        else:
            logging.info("Param --dry-run detected, mail didn't send")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days",
                        dest="days",
                        type=int,
                        required=False,
                        help="Days to calculate user expire access. Mandatory")
    parser.add_argument("-c", "--conf",
                        dest="config_file_path",
                        default=CONFIG_FILE_PATH,
                        help="Path to the config file in .ini format. Default: config.ini")
    parser.add_argument("-d", "--delete",
                        dest="delete",
                        action="store_true",
                        default=False,
                        help="Delete expired users instead of near expired")
    parser.add_argument("--dry-run",
                        dest="dry_run",
                        action="store_true",
                        default=False,
                        help="Dont send email either delete users, only print log")
    parser.add_argument("-l", "--log",
                        dest="log_level",
                        default=DEFAULT_LOGGING,
                        choices=['debug', 'info', 'warn', 'error'],
                        help="Log level for the application. Default: info")
    args = parser.parse_args()

    if args.days is None and not args.delete:
        parser.error('You need to specify one of [--delete] or [--days] param')
        exit(1)
    if args.days is not None and args.delete:
        parser.error('You need to specify only one of [--delete] or [--days] param')
        exit(1)

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

    if args.days is not None and args.days <= 0:
        parser.error("Days must be a int > 0")
        exit(-1)

    config = load_config(args.config_file_path)
    managers, users, managers_delete, users_delete = get_ldap_users(config, args.days)
    if args.delete:
        send_mail_delete(config, managers_delete, users_delete, args.dry_run)
        delete_ldap_users(config, users_delete, args.dry_run)
    else:
        send_mails(config, managers, users, args.days, args.dry_run)

    exit(0)


# MAIN.
if __name__ == '__main__':
    main()
