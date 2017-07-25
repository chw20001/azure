#!/usr/bin/env python
import getopt
import os
import sys
import re
import socket
import fcntl
import struct
import subprocess
import string
import array

NAT_IP_TYPE = 2
MIN_NET_INTF_COUNT = 1
INTERFACE = 'eth0'

def print_message(verbose, message):
    if verbose:
        sys.stdout.write(message)

def is_access_token_valid(access_token):
    import requests
    url = 'https://api.verisignrecursivedns.com/api/v1/vip_status'
    headers = {'Authorization': access_token}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code == 200:
        return True
    else:
        return False

def check_internet_connectivity_and_token():
    failed = False
    for port in [5043]:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect(('www.verisigndnsfirewall.com', port))
        except socket.error:
            failed = True
            break
    return not failed

def all_interfaces():
    max_possible = 128
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]
    namestr = names.tostring()
    lst = []
    for i in range(0, outbytes, 40):
        name = namestr[i:i+16].split('\0', 1)[0]
        ip   = namestr[i+20:i+24]
        lst.append((name, ip))
    return lst

def get_ip_address(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except:
        return

def get_management_network():
    mgmt_network = None
    try:
        str = raw_input("Enter the management subnet, in the form xxx.xxx.xxx.xxx/yy, followed by [ENTER]: ")

        parts = str.split('/')

        if len(parts) != 2:
            raise AssertionError

        socket.inet_aton(parts[0])

        masklen = int(parts[1])

        if masklen <= 0 or masklen > 32:
            raise AssertionError

        mgmt_network = str

    except:
        pass

    return mgmt_network

def is_ip_address_valid(ip_addr):
    valid = False

    try:
        socket.inet_aton(ip_addr)
        valid = True

    except:
        pass

    return valid

def ensure_exists(file):
    if not os.path.exists(file):
        with open(file, 'w') as fd:
            pass

def run_command(command):
    """
    Run a given command on the operating system.

    Keyword arguments:
    command -- the command to run with arguements (type list)
    """
    # run command and capture stdout and stderr
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = p.communicate()

    # check return code
    if p.returncode != 0:
        raise Exception('Command failed')

def get_gateway_from_subnet(subnet):
    parts = subnet.split('/')
    
    if len(parts) != 2:
        raise AssertionError
    subnet_packed = socket.inet_aton(parts[0])
    if len(subnet_packed) != 4:
        raise AssertionError
    last_octet = subnet_packed[3:]
    last_octet_int = ord(last_octet) + 1
    gateway_packed = subnet_packed[:3] + chr(last_octet_int)
    return socket.inet_ntoa(gateway_packed)

def generate_bind_config(ip):
    bind_config_file = """
options {
        listen-on port 53 {
                                INTERNAL_IP;
        };
        listen-on-v6 port 53 {
        };
        directory       "/var/named";
        recursion yes;
        dnssec-enable yes;
        dnssec-validation no;
        allow-query { any; };
        forwarders { 198.41.1.11; 198.41.2.22; };
        forward only;
        max-ncache-ttl 900;
        masterfile-format text;
        max-recursion-queries 100;
        max-recursion-depth 75;
};
 
logging {
        channel default_syslog {
                file "data/named.run";
                severity dynamic;
                print-time yes;
                print-severity yes;
        };
        category resolver { default_syslog; };
        channel "querylog" {
                file "data/querylog";
                severity dynamic;
                print-time yes;
                print-severity yes;
        };
        category queries { querylog; };
};

zone "internal.cloudapp.net" {
    type forward;
    forwarders {
        168.63.29.16;
    };
};
    """
    
    bind_config_file = string.replace(bind_config_file, 'INTERNAL_IP', 
                                      ip)
   
    f = open('/etc/named.conf', 'w')
    f.write(bind_config_file.strip())
    f.close()
 
def install_and_configure_bind(verbose, subnet):
    print_message(verbose, 'Checking prerequisites...\n')

    print_message(verbose, 'Network interfaces:\t')
    count = 0
    for name,ip in all_interfaces():
        if name != 'lo':
            count += 1
    if count >= MIN_NET_INTF_COUNT:
        print_message(verbose, 'PASS\n')
    else:
        print_message(verbose, 'FAILED\n')
        sys.exit('Incorrect number of interfaces.')

    print_message(verbose, 'Starting setup process...\n')
    ip = get_ip_address(INTERFACE)
    if ip is None:
        sys.exit("Interface does not exist, please check your entry and try again")
    # Install bind
    run_command(["/bin/yum","-y","install","bind"])

    # Make /var/named directory if it does not exist, and set permissions
    # to 0755.
    try:
        os.stat('/var/named')
    except:
        os.mkdir('/var/named')
    os.chmod('/var/named', 0755)

    # Lay down bind config
    generate_bind_config(ip)

    # Restart services
    print_message(verbose, 'Restarting services...')
    run_command(["/sbin/service","named","restart"])
    print_message(verbose, 'Complete\n')

    print_message(verbose, 'Bind Setup Complete\n')

def install_ip_updater():
    try:
        os.stat('/etc/ip-updater')
    except:
        os.mkdir('/etc/ip-updater')
    os.chown('/etc/ip-updater', 0, 0)
    os.chmod('/etc/ip-updater', 0755)
 
    ip_updater_script = """
#!/usr/bin/env python
import os
import signal
import requests
import ConfigParser
import dns.resolver
import logging
from time import sleep

SHUTTINGDOWN = False
IPUPDATESECS = 10
CONFIG_FILE = '/etc/ip-updater/ip-updater.conf'

def shutdown_handler(signum, frame):
   log.info("Received signal %d, shutting down gracefully." % signum)
   global SHUTTINGDOWN
   SHUTTINGDOWN = True

def myIPaddress():
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['64.6.64.6', '64.6.65.6']
    try:
        domain = 'myip.verisignrecursivedns.com'
        ip=my_resolver.query(domain, 'A')
    except dns.resolver.NoAnswer:
        return
    except dns.resolver.NoNameservers:
        return

    return ip[0].address

def main():
    url = 'https://api.verisignrecursivedns.com/api/v1/configs'
    access_token = config.get('account', 'access_token')
    config_id = config.get('account', 'config_id')
    nat_ip_type = config.get('account', 'nat_ip_type')

    log.info('Started IP updater')
    while not SHUTTINGDOWN:
        dic_nat_ip = {}
        nat_ip = myIPaddress()
        config_nat_ip = config.get('account', 'nat_ip')
        if nat_ip != config_nat_ip:
            dic_nat_ip[nat_ip] = int(nat_ip_type)
            source_ip_list = []
            source_ip_list.append(str(dic_nat_ip))
            payload = {'source_ip_address': source_ip_list}
            headers = {'Authorization': access_token}

            if config_id == "":
                r = requests.post(url, json=payload, headers=headers, verify=False)
            else:
                url = url+'/'+str(config_id)
                r = requests.put(url, json=payload, headers=headers, verify=False)

            if r.status_code == 200:
                config_id = r.json()['config']['config_id']
                cfgfile = open('/etc/ip-updater/ip-updater.conf','w')
                config.set('account', 'config_id', str(config_id))
                config.set('account', 'nat_ip', str(nat_ip))
                config.write(cfgfile)
                cfgfile.close()
                log.info("NAT IP for config ID %s changed to %s" % (config_id, nat_ip))
            else:
                log.error("Request ended with error: %s"%r.json()['message'])
        sleep(IPUPDATESECS)
        
config = ConfigParser.RawConfigParser()
config.read(CONFIG_FILE)

#Setup logging
logdir = config.get('logging', 'log_dir')
if not os.path.exists(logdir):
    os.makedirs(logdir)
logfn = config.get('logging', 'log_file')
logfile = os.path.join(logdir, logfn)

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] - %(name)s - %(message)s',
                    datefmt='%d/%b/%Y:%H:%M:%S %z',
                    filename=logfile)

log = logging.getLogger('IPUpdater')


try:
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    main()

except Exception as e:
    print 'ERROR: %s' % e
    """

    f = open('/usr/bin/ip-updater.py', 'w')
    f.write(ip_updater_script.strip())
    f.close()

    os.chown('/usr/bin/ip-updater.py', 0, 0)
    os.chmod('/usr/bin/ip-updater.py', 0755)


    init_script = """
#!/bin/bash
# chkconfig: 345 80 20
# description: IP Updater
# processname: ip-updater
# pidfile: /var/run/ip-updater.pid

PATH=/sbin:/usr/sbin:/bin:/usr/bin
NAME=ip-updater
DAEMON=/usr/bin/ip-updater.py
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME

[ -r /etc/default/$NAME ] && . /etc/default/$NAME
. /etc/init.d/functions

DAEMON_ARGS="$DAEMON_ARGS"

start()
{
        echo -n $"Starting $NAME: "
        nohup /usr/bin/python $DAEMON $DAEMON_ARGS >/dev/null 2>&1 &
        RETVAL=$?
        PID=$!
        echo $PID > $PIDFILE
        echo
        [ $RETVAL -eq 0 ] && touch /var/lock/subsys/$NAME
}

stop()
{
        echo -n $"Stopping $NAME: "
        killproc -p "$PIDFILE" $DAEMON
        RETVAL=$?
        [ -f "$PIDFILE" ] && rm -f "$PIDFILE"
        echo
        [ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/$NAME
}

restart () {
        stop
        start
}

RETVAL=0

case "$1" in
        start)
                status -p $PIDFILE >/dev/null
                RET=$?
                if [ $RET -ne 0 ];then
                        start
                fi
                ;;
        stop)
                stop
                ;;
        restart|reload|force-reload)
                restart
                ;;
        condrestart)
                [ -f /var/lock/subsys/$NAME ] && restart || :
                ;;
        status)
                echo -n "$NAME"
                status -p $PIDFILE
                RETVAL=$?
                ;;
        *)
                echo "Usage: $0 {start|stop|status|restart|reload|force-reload|condrestart}"
                RETVAL=1
esac

exit $RETVAL
    """
    
    f = open('/etc/init.d/ip-updater', 'w')
    f.write(init_script.strip())
    f.close()

    os.chown('/etc/init.d/ip-updater', 0, 0)
    os.chmod('/etc/init.d/ip-updater', 0755)

def install_iptables_services():
    run_command(["/bin/yum","-y","install","iptables-services"])

def install_nginx():
    # Install yum repo file for nginx so that we can install nginx
    nginx_repo = """
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/centos/7/$basearch/
gpgcheck=0
enabled=1
    """
    f = open('/etc/yum.repos.d/nginx.repo', 'w')
    f.write(nginx_repo.strip())
    f.close()
    os.chown('/etc/yum.repos.d/nginx.repo', 0, 0)
    os.chmod('/etc/yum.repos.d/nginx.repo', 0644)

    run_command(["/bin/yum","-y","install","nginx"])

def install_trafficcapture():
    try:
        os.stat('/etc/smtp-traffic-capturer')
    except:
        os.mkdir('/etc/smtp-traffic-capturer')
    os.chown('/etc/smtp-traffic-capturer', 0, 0)
    os.chmod('/etc/smtp-traffic-capturer', 0755)
 
    traffic_capture_script = """
import os
import socket
import fcntl
import struct
import logging
import smtpd
import asyncore
import ConfigParser

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

class SMTPTrafficCatcher(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data):
        log = logging.getLogger('SMTP')
        subject = ""
        start_index = data.find('Subject:')
        if start_index:
            start_index += len('Subject: ')
            end_index = data.find('\\n', start_index)
            subject = data[start_index:end_index]
        log.error(
            '%s:%i Subject: %s' % (
                peer[0], peer[1], subject))
        return


if __name__ == '__main__':
    config = ConfigParser.RawConfigParser()
    config.read('/etc/smtp-traffic-capturer/smtp-traffic-capturer.conf')
    logdir = config.get('logging', 'log_dir')
    if not os.path.exists(logdir):
        os.makedirs(logdir)
    logfn = config.get('logging', 'log_file')
    logfile = os.path.join(logdir, logfn)

    redirect_interface = config.get('interfaces', 'redirect_interface')

    logging.basicConfig(level=logging.ERROR,
                        format='[%(asctime)s] - %(name)s - %(message)s',
                        datefmt='%d/%b/%Y:%H:%M:%S %z',
                        filename=logfile)

    smtp_traffic_server = SMTPTrafficCatcher((get_ip_address(redirect_interface), 25), None)

    asyncore.loop()
    """

    f = open('/usr/bin/smtp-traffic-capturer.py', 'w')
    f.write(traffic_capture_script.strip())
    f.close()

    os.chown('/usr/bin/smtp-traffic-capturer.py', 0, 0)
    os.chmod('/usr/bin/smtp-traffic-capturer.py', 0755)

    init_script = """
#!/bin/bash
# chkconfig: 345 80 20
# description: SMTP Traffic capturer
# processname: smtp-traffic-capturer
# pidfile: /var/run/smtp-traffic-capturer.pid

PATH=/sbin:/usr/sbin:/bin:/usr/bin
NAME=smtp-traffic-capturer
DAEMON=/usr/bin/smtp-traffic-capturer.py
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME

[ -r /etc/default/$NAME ] && . /etc/default/$NAME
. /etc/init.d/functions

DAEMON_ARGS="$DAEMON_ARGS"

start()
{
        echo -n $"Starting $NAME: "
        nohup /usr/bin/python $DAEMON $DAEMON_ARGS >/dev/null 2>&1 &
        RETVAL=$?
        PID=$!
        echo $PID > $PIDFILE
        echo
        [ $RETVAL -eq 0 ] && touch /var/lock/subsys/$NAME
}

stop()
{
        echo -n $"Stopping $NAME: "
        killproc -p "$PIDFILE" $DAEMON
        RETVAL=$?
        [ -f "$PIDFILE" ] && rm -f "$PIDFILE"
        echo
        [ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/$NAME
}

restart () {
        stop
        start
}

RETVAL=0

case "$1" in
        start)
                status -p $PIDFILE >/dev/null
                RET=$?
                if [ $RET -ne 0 ];then
                        start
                fi
                ;;
        stop)
                stop
                ;;
        restart|reload|force-reload)
                restart
                ;;
        condrestart)
                [ -f /var/lock/subsys/$NAME ] && restart || :
                ;;
        status)
                status -p $PIDFILE
                RETVAL=$?
                ;;
        *)
                echo "Usage: $0 {start|stop|status|restart|reload|force-reload|condrestart}"
                RETVAL=1
esac

exit $RETVAL
    """
    
    f = open('/etc/init.d/smtp-traffic-capturer', 'w')
    f.write(init_script.strip())
    f.close()

    os.chown('/etc/init.d/smtp-traffic-capturer', 0, 0)
    os.chmod('/etc/init.d/smtp-traffic-capturer', 0755)

def install_logstash_forwarder():
    run_command(["/bin/yum", "-y", "install", \
                 "https://download.elastic.co/logstash-forwarder/binaries/logstash-forwarder-0.4.0-1.x86_64.rpm",
                 "logstash-forwarder"]) 

def generate_ip_updater_config(access_token, nat_ip_type):
    config_file = """
[account]
access_token = args_token
config_id =
nat_ip =
nat_ip_type = args_ip_type

[logging]
log_dir = /var/log
log_file = ip_updater.log
    """
    config_file = string.replace(config_file, 'args_token', access_token)
    config_file = string.replace(config_file, 'args_ip_type', str(nat_ip_type))
    f = open('/etc/ip-updater/ip-updater.conf', 'w')
    f.write(config_file)
    f.close()

def generate_iptables_config(interface, subnet):
    iptables_file = """*filter

# Allow unlimited traffic on loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow outgoing 80, 443, 5043 and 53 (tcp and udp)
-A OUTPUT -o eth -p tcp --dport 5043 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# Accept incomming TCP connections from eth on predefined ports, allow
# all outgoing.  Allow port 53 for TCP and UDP, because we are running bind on the same
# box.
# Currently allow: smtp(25) http(80) dns(53)
-A INPUT -i eth -s SUBNET -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT -i eth -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT -i eth -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT -i eth -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT -i eth -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth -m state --state NEW,ESTABLISHED -j ACCEPT

# Allow all incoming related to outgoing connections
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Enable logging for incoming
-A INPUT -i eth -m state --state NEW -j LOG --log-prefix "IPTABLES "

# Set the default policy on the input chain to DROP
-A INPUT -j DROP

COMMIT
"""
    iptables_file = string.replace(iptables_file, 'eth', interface)
    iptables_file = string.replace(iptables_file, 'SUBNET', subnet)
    f = open('/etc/sysconfig/iptables', 'w')
    f.write(iptables_file)
    f.close()

    rsyslog_file = """
:msg,contains,"IPTABLES " /var/log/iptables.log
"""

    f = open('/etc/rsyslog.d/iptables.conf', 'w')
    f.write(rsyslog_file)
    f.close()

    f = open('/var/log/iptables.log', 'a')
    try:
        os.utime('/var/log/iptables.log', None)
    finally:
        f.close()

def generate_nginx_config(interface):
    nginx_file = """
worker_processes 1;

events { worker_connections 1024; }

http {

        sendfile on;

        log_format scheme_combined '$scheme - $remote_addr - $remote_user [$time_local] '
                                   '$host "$request" $status $body_bytes_sent '
                                   '"$http_referer" "$http_user_agent"';

        server {
                listen redirect_ip:80;

                server_name ~^(.+)$;

                root /usr/share/nginx/html;

                access_log /var/log/nginx/access.log scheme_combined;
                error_log /var/log/nginx/error.log;

                location / {
                        # Rewrite rules can go here
                        rewrite ^ /index.html break;
                }
        }
}
    """
    redirect_ip = get_ip_address(interface)
    nginx_file = string.replace(nginx_file, 'redirect_ip', redirect_ip)
    f = open('/etc/nginx/nginx.conf', 'w')
    f.write(nginx_file)
    f.close()

    landing_page = """
<html>
  <head>
    <title>Verisign</title>
  </head>
  <body bgcolor=white>

    <table border="0" cellpadding="10">
      <tr>
        <td>
          <h1>Verisign</h1>
        </td>
      </tr>
    </table>

    <p>HTTP request redirected due to web categorization rule or known malicious site. </p>

  </body>
</html>
    """

    try:
        os.stat('/usr/share/nginx/html')
    except:
        os.mkdir('/usr/share/nginx/html')
    os.chmod('/usr/share/nginx/html', 0755)
    f = open('/usr/share/nginx/html/index.html', 'w')
    f.write(landing_page)
    f.close()

def generate_trafficcapture_config(interface):
    config_file = """
[interfaces]
redirect_interface = redir_int

[logging]
log_dir = /var/log
log_file = smtp_traffic_capture.log
    """
    config_file = string.replace(config_file, 'redir_int', interface)
    f = open('/etc/smtp-traffic-capturer/smtp-traffic-capturer.conf', 'w')
    f.write(config_file)
    f.close()

def generate_logstashforwarder_config(interface, cuid):
    ca_cert_file = """
-----BEGIN CERTIFICATE-----
MIIFSTCCBDGgAwIBAgIQaYeUGdnjYnB0nbvlncZoXjANBgkqhkiG9w0BAQsFADCB
vTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MTgwNgYDVQQDEy9W
ZXJpU2lnbiBVbml2ZXJzYWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAe
Fw0xMzA0MDkwMDAwMDBaFw0yMzA0MDgyMzU5NTlaMIGEMQswCQYDVQQGEwJVUzEd
MBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVj
IFRydXN0IE5ldHdvcmsxNTAzBgNVBAMTLFN5bWFudGVjIENsYXNzIDMgU2VjdXJl
IFNlcnZlciBTSEEyNTYgU1NMIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAvjgWUYuA2+oOTezoP1zEfKJd7TuvpdaeEDUs48XlqN6Mhhcm5t4LUUos
0PvRFFpy98nduIMcxkaMMSWRDlkXo9ATjJLBr4FUTrxiAp6qpxpX2MqmmXpwVk+Y
By5LltBMOVO5YS87dnyOBZ6ZRNEDVHcpK1YqqmHkhC8SFTy914roCR5W8bUUrIqE
zq54omAKU34TTBpAcA5SWf9aaC5MRhM7OQmCeAI1SSAIgrOxbIkPbh41JbAsJIPj
xVAsukaQRYcNcv9dETjFkXbFLPsFKoKVoVlj49AmWM1nVjq633zS0jvY3hp6d+QM
jAvrK8IisL1Vutm5VdEiesYCTj/DNQIDAQABo4IBejCCAXYwEgYDVR0TAQH/BAgw
BgEB/wIBADA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vY3JsLndzLnN5bWFudGVj
LmNvbS91bml2ZXJzYWwtcm9vdC5jcmwwDgYDVR0PAQH/BAQDAgEGMDcGCCsGAQUF
BwEBBCswKTAnBggrBgEFBQcwAYYbaHR0cDovL29jc3Aud3Muc3ltYW50ZWMuY29t
MGsGA1UdIARkMGIwYAYKYIZIAYb4RQEHNjBSMCYGCCsGAQUFBwIBFhpodHRwOi8v
d3d3LnN5bWF1dGguY29tL2NwczAoBggrBgEFBQcCAjAcGhpodHRwOi8vd3d3LnN5
bWF1dGguY29tL3JwYTAqBgNVHREEIzAhpB8wHTEbMBkGA1UEAxMSVmVyaVNpZ25N
UEtJLTItMzczMB0GA1UdDgQWBBTbYiD7fQKJfNI7b8fkMmwFUh2tsTAfBgNVHSME
GDAWgBS2d/ppSEefUxLVwuoHMnYH0ZcHGTANBgkqhkiG9w0BAQsFAAOCAQEAGcyV
4i97SdBIkFP0B7EgRDVwFNVENzHv73DRLUzpLbBTkQFMVOd9m9o6/7fLFK0wD2ka
KvC8zTXrSNy5h/3PsVr2Bdo8ZOYr5txzXprYDJvSl7Po+oeVU+GZrYjo+rwJTaLE
ahsoOy3DIRXuFPqdmBDrnz7mJCRfehwFu5oxI1h5TOxtGBlNUR8IYb2RBQxanCb8
C6UgJb9qGyv3AglyaYMyFMNgW379mjL6tJUOGvk7CaRUR5oMzjKv0SHMf9IG72AO
Ym9vgRoXncjLKMziX24serTLR3x0aHtIcQKcIwnzWq5fQi5fK1ktUojljQuzqGH5
S5tV1tqxkju/w5v5LA==
-----END CERTIFICATE-----
    """
    f = open('/etc/pki/tls/certs/logstash-forwarder.crt', 'w')
    f.write(ca_cert_file.strip())
    f.close()
    os.chown('/etc/pki/tls/certs/logstash-forwarder.crt', 0, 0)
    os.chmod('/etc/pki/tls/certs/logstash-forwarder.crt', 0644)

    forwarder_file = """
{
  "network": {
    "servers": [ "dashboard.verisignrecursivedns.com:5043" ],
    "ssl ca": "/etc/pki/tls/certs/logstash-forwarder.crt",
    "timeout": 15
  },
  "files": [
    {
      "paths": [
        "/var/log/nginx/access.log"
       ],
      "fields": {
          "type": "webserver",
          "cuid": "XXXXXXXXX",
          "appIP": "YYYYYYYYY",
          "appversion": "2"
      }
    },
    {
      "paths": [
        "/var/log/iptables.log"
       ],
      "fields": {
          "type": "firewall",
          "cuid": "XXXXXXXXX"
      }
    },
    {
      "paths": [
        "/var/log/smtp_traffic_capture.log"
       ],
      "fields": {
          "type": "traffic_capture",
          "cuid": "XXXXXXXXX"
      }
    }
  ]
}
    """
    forwarder_file = string.replace(forwarder_file, 'XXXXXXXXX', cuid)
    forwarder_file = string.replace(forwarder_file, 'YYYYYYYYY', \
                                    get_ip_address(interface))
    f = open('/etc/logstash-forwarder.conf', 'w')
    f.write(forwarder_file)
    f.close()

       
def configure_appliance(verbose, cuid, access_token, subnet):
    print_message(verbose, 'Beginning configuration of appliance\n')

    # Move this to after we register the NATs and register the appliance IP's
    # print_message(verbose, 'Checking internet connectivity:\t')
    # if check_internet_connectivity():
    #     print_message(verbose, 'PASS\n')
    # else:
    #     print_message(verbose, 'FAILED\n')
    #     sys.exit('No connectivity to dashboard.verisigndnsfirewall.com.')

    print_message(verbose, 'Installing IP updater...\n')
    install_ip_updater()
    
    print_message(verbose, 'Installing iptables-services...\n')
    install_iptables_services()

    print_message(verbose, 'Installing nginx...\n')
    install_nginx()
      
    print_message(verbose, 'Installing traffic capture script...\n')
    install_trafficcapture()

    print_message(verbose, 'Installing logstash forwarder...\n')
    install_logstash_forwarder()

    print_message(verbose, 'Configuring IP updater...\n')
    generate_ip_updater_config(access_token, NAT_IP_TYPE)
    
    print_message(verbose, 'Configuring iptables...\n')
    generate_iptables_config(INTERFACE, subnet)

    print_message(verbose, 'Configuring nginx...\n')
    generate_nginx_config(INTERFACE)

    print_message(verbose, 'Configuring traffic capture...\n')
    generate_trafficcapture_config(INTERFACE)
    
    print_message(verbose, 'Configuring logstash forwarder...\n')
    generate_logstashforwarder_config(INTERFACE, cuid)

    print_message(verbose, 'Restarting services...\n')
    run_command(["/sbin/service","nginx","restart"])
    run_command(["/sbin/service","iptables","restart"])
    run_command(["/sbin/service","rsyslog","restart"])
    run_command(["/sbin/service","logstash-forwarder","restart"])
    run_command(["/sbin/service","smtp-traffic-capturer","restart"])
    run_command(["/sbin/service","ip-updater","restart"])

    print_message(verbose, 'Complete.\n')
 
    return

def verify_subnet(subnet):
    parts = subnet.split('/')
    
    if len(parts) != 2:
        raise AssertionError

    socket.inet_aton(parts[0])
    masklen = int(parts[1])
      
    if masklen <= 0 or masklen > 32:
        raise AssertionError


if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "s:c:a:",["subnet=",
                                                     "cuid=",
                                                     "access_token="])

    subnet = ''
    cuid = ''
    access_token = ''
    for opt, arg in opts:
        if opt in ("-s", "--subnet"):
            subnet = arg
        elif opt in ("-c", "--cuid"):
            cuid = arg
        elif opt in ("-a", "--auth"):
            access_token = arg
        
    if subnet == '' or cuid == '' or (not cuid.isdigit()) or \
       access_token == '':
        sys.exit(2)

    run_command(["/bin/yum","-y","install","python-requests"])
    run_command(["/bin/yum","-y","install","python-dns"])

    if not is_access_token_valid(access_token):
        sys.exit(2)

    verify_subnet(subnet)
             
    install_and_configure_bind(False, subnet)
    configure_appliance(False, cuid, access_token, subnet)
