#!/usr/bin/env python3
"""Retrieves external ip of this machine and reports it via e-mail

Required modules: python-nmap and python-gnupg"""

import urllib.request, urllib.error, urllib.parse
import re
import warnings
import os
import smtplib
import argparse
import sys
import imaplib
import email
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message

NMAP_AVAIL = False
try:
    import nmap
    NMAP_AVAIL = True
except ImportError:
    warnings.warn("nmap module not found. Reverting to ip reporting only")
GPG_AVAIL = False
try:
    import gnupg
    GPG_AVAIL = True
except ImportError:
    warnings.warn("gnupg module not found.\nWill not sign ip report e-mails or"
            " check signatures")

#Monkeypatch for showwarning
def _pretty_warning(message, category=UserWarning, filename='', lineno =-1):
    print("WARNING:", message)

warnings.showwarning = _pretty_warning

IP_REGEX = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

IP_SITES = [r"https://shtuff.it/myip/short", r"https://icanhazip.com",
        r"http://ifconfig.me", r"http://checkip.dyndns.org"]

LOGIN_HEADERS = ["user", "password", "smtp server", "imap server",
"from", "gpg key", "gpg password"]

def lazy_attribute(function):
    """Decorator for use in creating lazy attributes"""
    lazy_name = '_lazy_' + function.__name__
    @property
    def _lazy_attribute(self):
        """Sets attribute if not evaluted; otherwise returns value"""
        if not hasattr(self, lazy_name):
            setattr(self, lazy_name, function(self))
        return getattr(self, lazy_name)
    return _lazy_attribute

class ConfigError(Exception):
    """Exception used to handle bad configuration files"""
    def __init__(self, message):
        super(ConfigError, self).__init__(self, message)

class IPRetrievalError(Exception):
    """
    Exception used to handle case where IP cannot be retrieved
    """
    def __init__(self, message):
        super(IPRetrievalError, self).__init__(self, message)

def update_service(service_name, hostname, ip_str, port, local_ip=None):
    """Updates config file for given service"""
    SUPPORTED_SERVICES[service_name](hostname, ip_str, port, local_ip=local_ip)

def update_ssh(hostname, ip_str, port, local_ip=None):
    """Update .ssh/config with given information"""

    if local_ip is not None:
        update_ssh(hostname + "_local", local_ip, port)
    other_data = []
    cur_data = ["Host {}".format(hostname), "    HostName {}".format(ip_str)]
    if port != "NOT FOUND":
        cur_data.append("    Port {}".format(port))
    with open(os.path.expanduser(r"~/.ssh/config"), 'r') as config_file:
        found_prev_data = False
        for line in config_file:
            #Second check here is because config file always uses topmost
            if ("Host {}".format(hostname) == line.rstrip()
                    and not found_prev_data):
                found_prev_data = True
                try:
                    #Gather up any non-updatable info already in config file
                    line = next(config_file)
                    while "Host " not in line:
                        if "HostName " not in line and ("Port " not in line or
                                port == "NOT FOUND"):
                            cur_data.append(line.rstrip())
                        line = next(config_file)
                    other_data.append(line.rstrip())
                except StopIteration:
                    break
            else:
                other_data.append(line.rstrip())

    cur_data.extend(other_data)
    cur_data.append("")#For newline at end of file
    with open(os.path.expanduser(r"~/.ssh/config"), 'w') as config_file:
        config_file.write("\n".join(cur_data))

SUPPORTED_SERVICES = {"ssh":update_ssh}

def parse_service(service_dict, string_desc):
    """Takes "service:port" string and adds service to dictionary"""
    service = string_desc.split(":", 1)
    service[1] = service[1].strip()
    try:
        #Always sanitize your input...
        if service[0] in SUPPORTED_SERVICES:
            if str(service[1]).isnumeric() or service[1] == "NOT FOUND":
                service_dict[service[0]] = service[1]
        else:
            warnings.warn(
                "Unsupported service {} in report from {}.".format(service[0]))
    except IndexError:
        #Ignore if there's nothing after the colon
        pass

def get_local_ip(verbose=False):
    """Tries to obtain local ip"""
    if verbose:
        print("Attempting to find local ip by hostname...")
    local_ip = socket.gethostbyname(socket.gethostname())
    if local_ip.startswith("127."):
        if verbose:
            print("Failed. Attempting to find local ip via socket connection \
to 8.8.8.8...")
        try:
            cur_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cur_sock.connect(("8.8.8.8", 80))
            local_ip = cur_sock.getsockname()[0]
        except socket.error:
            pass
    if local_ip.startswith("127."):
        raise IPRetrievalError("Could not find local ip")
    return local_ip

def get_own_ip(verbose=False):
    """Tries to obtain ip from several websites"""

    trial_ip = None
    confirmation_count = 0
    for site in IP_SITES:
        if verbose:
            print("Retrieving IP from {}".format(site))
        try:
            data_str = urllib.request.urlopen(site, None, 2).read()
            data_str = data_str.decode('utf-8')
            ip_str = IP_REGEX.search(data_str).group()
            if trial_ip is not None:
                if ip_str == trial_ip:
                    if verbose:
                        print("IP confirmed.")
                    return ip_str
            else:
                trial_ip = ip_str
                if verbose:
                    print("IP found: {}. Confirming...".format(ip_str))
                confirmation_count = 1
        except (urllib.error.URLError, socket.timeout):
            continue

    if confirmation_count == 1:
        warnings.warn("IP address not confirmed.")
        return trial_ip

    raise IPRetrievalError("IP address not found after four attempts.")

def verify(text, signature, trust_level="full", accept_bad_keys=False,
        verbose=False):
    """Checks whether signature is valid for given text

    Returns True if signature is valid and trusted at given level, and False
    otherwise. Also returns False for expired or revoked keys unless
    accept_bad_keys is set to True. Valid trust_level options are "never",
    "marginal", "full", and "ultimate". Issues warnings if there is a problem
    with the key or the trust level is less than full.
    """
    if not GPG_AVAIL:
        warnings.warn("Could not verify signature")
        return trust_level == "never"

    gpg = gnupg.GPG()
    if verbose:
        print("Analyzing signature...")
    with open("/tmp/temp.asc", "w") as sig_file:
        sig_file.write(signature)
    verify_status = gpg.verify_data("/tmp/temp.asc", text)
    trust_dict = {"undefined":verify_status.TRUST_UNDEFINED,
            "never":verify_status.TRUST_NEVER,
            "marginal":verify_status.TRUST_MARGINAL,
            "full":verify_status.TRUST_FULLY,
            "ultimate":verify_status.TRUST_ULTIMATE}
    if verify_status.trust_level is None:
        if verbose:
            print("Signature invalid!")
        return False
    if verify_status.key_status is not None:
        warnings.warn(
                "Issue with key {} detected. Key status: {}".format(
                    verify_status.key_id, verify_status.key_status))
        if not accept_bad_keys:
            return False
    if verify_status.trust_level >= trust_dict[trust_level]:
        if verbose:
            print("Signature valid at trust level {} or higher".format(
                    trust_level))
        if verify_status.trust_level < trust_dict["full"]:
            warnings.warn("Trust level {} for signature".format(
                verify_status.trust_level))
        return True
    if verbose:
        print("Signature not valid at designated trust level {}".format(
            trust_level))
        print("Actual trust level: {}".format(verify_status.trust_text))
    return False

def parse_ssh(report_email):
    """Updates ssh config file with new ip addresses and ports"""
    print(report_email)

def read_config(filename, verbose=False):
    """Reads configuration from file"""
    config = {"recipients":{}}
    if verbose:
        print("Reading configuration from {}".format(filename))
    with open(filename) as file_:
        for line in file_:
            if ":" in line:
                line = line.split(":", 1)

                section = line[0].lower().strip()
                #Get hostname for which to receive report
                if section == "subscriptions":
                    config["subscriptions"] = line[1].strip().split()
                elif section == "trust level":
                    config["trust level"] = line[1].strip().lower()
                #Get e-mail address to send report to
                elif section == "recipient":
                    cur_rec = line[1].strip()
                #Get which services to send port information for
                elif section == "services":
                    service_list = line[1].split(",")
                    service_list = [x.strip() for x in service_list]
                    service_list = [x for x in service_list if x]
                    config["recipients"][cur_rec] = service_list
                #Get e-mail address/username to send from
                elif section in LOGIN_HEADERS:
                    config[section] = line[1].strip()
                else:
                    warnings.warn(
                            "Unrecognized section \"{}\" in config \
file {}".format(section, filename))

    return config

def get_port_info(verbose=False):
    """Retrieves nmap-like info on port usage"""
    if verbose:
        print("Checking port usage...")
    hostname = socket.gethostname()
    home = "127.0.0.1"

    if not NMAP_AVAIL:
        return {}
    nm = nmap.PortScanner()
    nm.scan(home, "22-2222")
    services = nm[home].get('tcp', {})
    #TODO: Figure out and include udp
    services = {services[port]['name'] : port for port in list(services.keys())}

    return services

def log_ip(ip_str, log_file=os.path.expanduser(r"~/.ip/ip.log"),
        verbose=False):
    """Logs given ip string to file"""
    if verbose:
        print("Writing ip to {}".format(log_file))
    with open(log_file, 'w') as file_:
        file_.write(ip_str)

def get_logged_ip(log_file=os.path.expanduser(r"~/.ip/ip.log"),
        verbose=False):
    """Returns previously logged ip"""
    if verbose:
        print("Retrieving ip from {}".format(log_file))
    with open(log_file) as file_:
        return file_.read().strip()

class IpReporter(object):
    """Sends and retrieves ip reports via email"""

    def __init__(self, config_file=os.path.expanduser(
        r"~/.ip/.iprc"), verbose=False):
        self.verbose = verbose
        self.config = read_config(config_file, verbose=self.verbose)
        if GPG_AVAIL:
            self.gpg = gnupg.GPG()
            #Get gpg key
            try:
                self.key_id = self.config["gpg key"]
            except KeyError:
                warnings.warn("No gpg key specified. Will not sign ip report"
                        " e-mails")
                self.key_id = None

        self.report_texts = {}
        #Dictionary of recipient:e-mail text for reports
        self.report_emails = []
        #List of emails to be sent out

    @lazy_attribute
    def ip_str(self):
        """String representing ip address of this computer"""
        return get_own_ip(verbose=self.verbose)

    @lazy_attribute
    def local_ip(self):
        """String representing local ip of this computer"""
        return get_local_ip(verbose=self.verbose)

    @lazy_attribute
    def service_info(self):
        """Dictionary representing port usage of this computer"""
        return get_port_info(verbose=self.verbose)

    @lazy_attribute
    def hostname(self):
        """String representing hostname of this computer"""
        return socket.gethostname()


    def retrieve_reports(self, verbose=False):
        """Retrieves reports for ip address of other computers"""
        #Log onto IMAP server
        if verbose:
            print("Logging onto {}...".format(self.config["imap server"]))
        mail = imaplib.IMAP4_SSL(self.config["imap server"])
        mail.login(self.config["user"], self.config["password"])
        if verbose:
            print("Searching for latest reports...")
        #WARNING: Following line is gmail specific for now
        mail.select("inbox")
        report_emails = []
        for host in self.config["subscriptions"]:
            latest_id = mail.uid('search', None,
                '(HEADER Subject "IP address report for {}")'.format(host)
                )
            try:
                latest_id = latest_id[1][0].split()[-1]
                report_emails.append(mail.fetch(latest_id, "(RFC822)"))
            except IndexError:
                warnings.warn("No ip report found for {}".format(host))

        return report_emails

    def update_subscriptions(self, verbose=False):
        """Updates config files for known services and prints others"""
        report_emails = self.retrieve_reports(verbose=verbose)
        for email_ in report_emails:
            email_ = email.message_from_string(email_[1][0][1])
            other_host = None
            other_ip = None
            other_local_ip = None
            other_services = {}
            signature = None
            for part in email_.walk():
                if part.get_content_type() == 'text/plain':
                    signed_text = str(part).split("\n", 1)[1]
                    report_text = part.get_payload()
                    for line in report_text.split("\n"):
                        if "Hostname" in line:
                            other_host = line.split(":", 1)[1].strip()
                        #TODO: Add option to take local
                        elif "Local IP" in line:
                            other_local_ip = line.split(":", 1)[1].strip() 
                            if not IP_REGEX.match(other_ip):
                                other_local_ip = None
                        elif line[:2] == "IP":
                            other_ip = line.split(":", 1)[1].strip()
                            if not IP_REGEX.match(other_ip):
                                other_ip = None
                        elif ":" in line:
                            parse_service(other_services, line)

                if part.get_content_type() == 'application/pgp-signature':
                    if verbose:
                        print("Signature found.")
                    signature = part.get_payload(decode=True)

            if ((signature is None and self.config.get("trust level",
                "full") != "never")  or not verify(signed_text, signature,
                    trust_level=self.config.get("trust level", "full"),
                    verbose=verbose)):
                warnings.warn(
                    "Unaccepted signature. Ignoring report for "
                    "{}".format(other_host))
            else:
                if verbose:
                    print("Updating service config files...")
                for service in other_services:
                    if verbose:
                        print("Updating service {} for {}".format(
                            service, other_host))
                    update_service(service, other_host, other_ip,
                            other_services[service], local_ip=other_local_ip)

    def report_ip(self, force=False, verbose=False):
        """Generate and send all e-mails"""
        if not force and self.ip_str == get_logged_ip():
            if verbose:
                print("IP unchanged from last report.")
            return
        if verbose:
            print("Preparing and sending reports...")
        self.generate_email_texts()
        self.generate_emails_from_texts()
        self.send_emails()
        if verbose:
            print("Logging new ip...")
        log_ip(self.ip_str)

    def __str__(self):
        return self.ip_str

    def send_emails(self):
        """Sends all report e-mails"""
        #Check that all necessary info is in config
        try:
            server = self.config["smtp server"]
            user = self.config["user"]
            pwd = self.config["password"]
        except KeyError:
            raise ConfigError(
                "Server, user, and password must all be specified in "
                "configuration file.")

        #Log onto server
        if self.verbose:
            print("Logging onto e-mail server")
        server = smtplib.SMTP(server)
        server.ehlo()
        server.starttls()
        server.login(user, pwd)

        for email_ in self.report_emails:
            if self.verbose:
                print("Sending report to {}".format(email_["To"]))
            server.sendmail(email_["From"], email_["To"],
                    email_.as_string())

        #Logoff server
        server.quit()
        if self.verbose:
            print("Logging off e-mail server")

    def generate_email_texts(self):
        """Generate text of all ip report e-mails"""
        for recipient in list(self.config["recipients"].keys()):
            if self.verbose:
                print("Generating report for {}".format(recipient))
            report_text = ["Hostname: {}".format(self.hostname)]
            report_text.append("IP: {}".format(self.ip_str))
            report_text.append("Local IP: {}".format(self.local_ip))
            report_text.extend(["{}: {}".format(service,
                self.service_info.get(service, "NOT FOUND")) for service in
                self.config["recipients"][recipient]])
            self.report_texts[recipient] = "\r\n".join(report_text)

    def generate_emails_from_texts(self):
        """Generate email objects from report texts"""
        for recipient in list(self.report_texts.keys()):
            if self.verbose:
                print("Generating e-mail for {}".format(recipient))
            base_msg = MIMEText(self.report_texts[recipient], 'plain')
            if self.key_id is not None:
                cur_msg = MIMEMultipart(_subtype="signed", micalg="pgp-sha1")
                cur_msg.attach(base_msg)
                #Set up signature
                signature = str(self.gpg.sign(base_msg.as_string(),
                    detach=True, keyid=self.key_id,
                    passphrase=self.config["gpg password"]))
                sign_msg = Message()
                sign_msg['Content-Type'] = 'application/pgp-signature; '\
                'name="signature.asc"'
                sign_msg['Content-Description'] = 'OpenPGP digital '\
                'signature'
                sign_msg.set_payload(signature)
            else:
                cur_msg = MIMEMultipart()
                cur_msg.attach(base_msg)
            #Set header information
            cur_msg['From'] = self.config.get("from", self.config["user"])
            cur_msg['To'] = recipient
            cur_msg['Subject'] = "IP address report for {}".format(
            self.hostname)
            #Attach signature (if possible)
            if self.key_id is not None:
                cur_msg.attach(sign_msg)
            self.report_emails.append(cur_msg)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Tools for keeping track of ip address')
    parser.add_argument("-v", "--verbose",
            help="increase output verbosity", action="store_true")
    parser.add_argument("-e", "--echo", help="display ip address",
            action="store_true")
    parser.add_argument("-l", "--local", help="display local ip",
            action="store_true")
    parser.add_argument("-r", "--report", help="report ip address by e-mail",
            action="store_true")
    parser.add_argument("-u", "--update",
            help="receive report and update addresses for various services",
            action="store_true")
    parser.add_argument("-f", "--force",
            help="force e-mail report, even if ip does not appear to have"
            " changed; implies --report",
            action="store_true")
    #Print help if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    #Parse arguments
    args = parser.parse_args()

    ipr = IpReporter(verbose=args.verbose)
    if args.update:
        ipr.update_subscriptions(verbose=args.verbose)
    #Initialize reporter
    if args.report or args.force:
        ipr.report_ip(force=args.force, verbose=args.verbose)
    if args.echo:
        print(ipr)
    if args.local:
        print(ipr.local_ip)
