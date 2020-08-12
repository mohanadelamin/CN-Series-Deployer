#!/usr/bin/env python3
# CN-Series-Deployer is a script to deploy and Configure Palo Alto Networks CN-Series.
#
# Authored by Mohanad Elamin (melamin@paloaltonetworks.com)
#

__author__ = "Mohanad Elamin @mohanadelamin"
__version__ = "1.0"
__license__ = "MIT"

import sys
import argparse
import re
import time
import base64
import json
import xml.etree.ElementTree as ET
from xml.dom.minidom import parse, parseString
from pandevice.base import PanDevice
from pandevice.panorama import Panorama, DeviceGroup, Template, TemplateStack
from pandevice.errors import PanDeviceError
from logging import basicConfig as logging_basicConfig, \
    addLevelName as logging_addLevelName, \
    getLogger as logging_getLogger, \
    log as logging_log, \
    DEBUG   as logging_level_DEBUG, \
    INFO    as logging_level_INFO, \
    WARN    as logging_level_WARN, \
    ERROR   as logging_level_ERROR, \
    debug   as debug, \
    info    as info, \
    warn    as warn, \
    error   as error
from paramiko.client import AutoAddPolicy
from paramiko.client import SSHClient as SSH_Client
from paramiko.ssh_exception import \
    BadHostKeyException as SSH_BadHostKeyException, \
    AuthenticationException as SSH_AuthenticationException, \
    SSHException as SSH_SSHException
from paramiko_expect import SSHClientInteraction
from signal import signal as signal_set_handler, SIGINT as signal_SIGINT


K8S_BASE_URL = 'https://raw.githubusercontent.com/mohanadelamin/CN-Series-Deployer/master/yamls/native/'
OPENSHIFT_BASE_URL = 'https://raw.githubusercontent.com/mohanadelamin/CN-Series-Deployer/master/yamls/openshift/'


def custom_signal_handler(signal, frame):
    """Very terse custom signal handler
    This is used to avoid generating a long traceback/backtrace
    """
    warn("Signal {} received, exiting".format(str(signal)))
    sys.exit(1)


def get_args():
    """
    Supports the command-line arguments listed below.
    """

    parser = argparse.ArgumentParser(description='Process args for Panorama and K8S configuration:')
    parser.add_argument('--pn_ip', required=True, action='store', help='Panorama management IP address')
    parser.add_argument('--pn_user', required=True, action='store', help='Panorama username')
    parser.add_argument('--pn_pass', required=True, action='store', help='Panorama Password')
    parser.add_argument('--k8s_ip', required=True, action='store', help='K8S master node IP address')
    parser.add_argument('--k8s_user', required=True, action='store', help='Panorama username')
    parser.add_argument('--k8s_pass', required=True, action='store', help='Panorama Password')
    parser.add_argument('--k8s_type', required=True, default='k8s', action='store', help='Cluster Type, k8s or openshift.')
    parser.add_argument('--k8s_port', required=True, default='6443', action='store', help='k8s port, default 6443')
    parser.add_argument('--k8s_mode', required=True, default='lite', action='store', help='deployment mode. lite or full')
    parser.add_argument('--k8s_name', required=True, action='store', help='K8S Cluster name')
    parser.add_argument('--pn_dg', required=True, action='store', help='Panorama device group')
    parser.add_argument('--pn_tmpl', required=True, action='store', help='Panorama Collector Group')
    parser.add_argument('--pn_cg', required=True, action='store', help='Panorama device group')
    parser.add_argument('--auth_code', required=True, action='store', help='CN-Series Auth_code')
    parser.add_argument('--tokens', required=True, default=1, action='store', help='Number of CN-Series tokens.')

    args = parser.parse_args()
    return args


def ssh_login(host, username, password):
    r = SSH_Client()
    r.load_system_host_keys()
    r.set_missing_host_key_policy(AutoAddPolicy())

    info("Trying to open a SSH connection to {}".format(host))

    try:
        r.connect(host, username=username, password=password)
    except SSH_BadHostKeyException as errstr:
        error("SSH host key for {0} could not be verified: {1}".format(host, errstr))
        return None
    except SSH_AuthenticationException:
        error("SSH authentication failed for {}".format(host))
        return None
    except SSH_SSHException as errstr:
        error("Unknown SSH error while connecting to {0}: {1}".format(host, errstr))
        return None
    except OSError as err:
        error("Can't connect to SSH server {0}: '{1}'".format(host, err))
        return None
    except:
        error("Unknown error encountered while connecting to SSH server {}".format(host))
        return None

    info("SSH connection to {} opened successfully".format(host))
    return r


def create_panos_device(ip, username, password):
    # Create PAN-OS device am make sure connection can be created. Wait for 5 minutes
    timeout = time.time() + 60 * 5  # 5 min from now
    ready = False
    while time.time() < timeout:
        try:
            pn_api_conn = Panorama(ip, username, password)
        except PanDeviceError as msg:
            error("PAN-OS is not ready trying again!")
            time.sleep(5)
        else:
            info("PAN-OS device API connection created!")
            ready = True
            break
    # Make sure PAN-OS is ready to accept commands. wait for 5 minutes
    timeout = time.time() + 60 * 5
    if ready:
        if wait_for_panos(pn_api_conn, timeout):
            return pn_api_conn
    else:
        return False


def wait_for_panos(pn_api_conn, timeout):
    time.sleep(5)
    while time.time() < timeout:
        try:
            element_response = pn_api_conn.op(cmd="show jobs all")
        except PanDeviceError as msg:
            error("PAN-OS is not ready yet. trying again!")
            time.sleep(5)
        else:
            jobs = element_response.findall('.//job')
            if check_jobs(jobs):
                info("No pending jobs")
                return True
    return False


def check_jobs(jobs):
    for j in jobs:
        status = j.find('.//status')
        if status is None or status.text != 'FIN':
            return False

    return True


def check_panos_version(pn_api_conn):
    try:
        element_response = pn_api_conn.op(cmd="show system info")
    except PanDeviceError as msg:
        error(msg)
        time.sleep(5)
    else:
        version = element_response.find('.//sw-version')
        return version.text


def check_template_stack(pn_api_conn, template_stack):
    try:
        element_response = pn_api_conn.op(cmd="show template-stack")
    except PanDeviceError as msg:
        error(msg)
        time.sleep(5)
    else:
        template_stacks = element_response.findall('.//entry')
        for n in template_stacks:
            if template_stack == n.attrib['name']:
                return True
        return False


def check_device_group(pn_api_conn, dg):
    try:
        element_response = pn_api_conn.op(cmd="show devicegroups")
    except PanDeviceError as msg:
        error(msg)
        time.sleep(5)
    else:
        device_groups = element_response.findall('.//entry')
        for n in device_groups:
            if dg == n.attrib['name']:
                return True
        return False


def configure_template(pn_ssh_conn, template):
    panorama_config_prompt = '.*# '
    with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
        interact.send('configure')
        interact.expect(panorama_config_prompt)
        interact.send('set template {} config  vsys vsys1'.format(template))
        interact.expect(panorama_config_prompt)
        interact.send('set template {} settings default-vsys vsys1'.format(template))
        interact.expect(panorama_config_prompt)
        interact.send('exit')
        info("Template {} Created".format(template))


def configure_template_stack(pn_ssh_conn, template_stack):
    panorama_config_prompt = '.*# '
    with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
        interact.send('configure')
        interact.expect(panorama_config_prompt)
        interact.send('set template-stack {} settings'.format(template_stack))
        interact.expect(panorama_config_prompt)
        interact.send('set template-stack {} templates {}'.format(template_stack,template_stack + '-tmp'))
        interact.expect(panorama_config_prompt)
        interact.send('exit')
        info("Template Stack {} Created".format(template_stack))


def configure_device_group(pn_ssh_conn, dg):
    panorama_config_prompt = '.*# '
    with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
        interact.send('configure')
        interact.expect(panorama_config_prompt)
        interact.send('set device-group {}'.format(dg))
        interact.expect(panorama_config_prompt)
        interact.send('exit')


def check_k8s_plugin(pn_api_conn):
    try:
        element_response = pn_api_conn.op(cmd="show system info")
    except PanDeviceError as msg:
        error(msg)
        time.sleep(5)
    else:
        plugins_versions = element_response.findall('.//pkginfo')
        for v in plugins_versions:
            if "kubernetes" in v.text:
                return v.text
        return None


def update_plugin_list(pn_api_conn):
    try:
        element_response = pn_api_conn.op(cmd="request plugins check")
    except PanDeviceError as msg:
        error(msg)
        sys.exit()
    else:
        plugins_versions = element_response.find('.//result')
        if 'updated' in plugins_versions.text:
            info(plugins_versions.text)
        else:
            error('Plugin list update failed. Please check panorama connectivity of install the plugin manually.')
            sys.exit()


def find_latest_k8s_plugin(pn_api_conn):
    k8s_list = []
    k8s_latest_plugin = {
        'name': '',
        'downloaded': ''
    }

    try:
        element_response = pn_api_conn.op(cmd="show plugins packages")
    except PanDeviceError as msg:
        error(msg)
        sys.exit()
    else:
        plugin_entries = element_response.findall('.//entry')

        for p in plugin_entries:
            p_version = p.find('.//pkg-file')
            if 'kubernetes' in p_version.text and not re.match(r".*-b.*", p_version.text):
                k8s_list.append(p_version.text)

        k8s_latest_plugin['name'] = sorted(k8s_list, reverse=True)[0]

        # Check if the latest plugin is downloaded
        for p in plugin_entries:
            if p.find('.//pkg-file').text == k8s_latest_plugin['name']:
                k8s_latest_plugin['downloaded'] = p.find('.//downloaded').text
        info("Latest kubernetes plugin available is {}".format(k8s_latest_plugin['name']))
        return k8s_latest_plugin


def download_plugin(pn_ssh_conn, plugin):
    try:
        panorama_op_prompt = '.*> '
        with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
            interact.send("request plugins download file {}".format(plugin))
            interact.expect(panorama_op_prompt)
            interact.send('exit')
            info("Plugin {} downloading.".format(plugin))
    except:
        error("I couldn't download the kubernetes plugin. Try to download it manually.")
        sys.exit()


def install_k8s_plugin(pn_ssh_conn, plugin):
    try:
        panorama_op_prompt = '.*> '
        with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
            interact.send("request plugins install {}".format(plugin))
            interact.expect(panorama_op_prompt)
            interact.send('exit')
            info("Plugin {} installed".format(plugin))
    except:
        error("I couldn't install the kubernetes plugin. Try to install it manually.")
        sys.exit()


def activate_license(pn_ssh_conn, auth_code, tokens=1):
    # Add CN-Series auth code
    try:
        info("Applying CN-Series Authcode {} and activating {} token(s)".format(auth_code, tokens))
        panorama_op_prompt = '.*> '
        with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
            interact.send("request plugins kubernetes set-license-tokens authcode {} token-count {}".format(auth_code, tokens))
            interact.expect(panorama_op_prompt)
            authcode_output = interact.current_output_clean
            if 'Error' in authcode_output:
                error(authcode_output.split('\n')[-3])
                error("Auth code can not be added. CN-Series can run for 4 hours. without license.")
            else:
                info("CN-Series license auth code {} added and {} tokens activated".format(auth_code,tokens))
    except:
        error("Auth code can not be added. CN-Series can run for 4 hours. without license.")


def run_ssh_command(ssh_conn, command):
    if ssh_conn:
        stdin, stdout, stderr = ssh_conn.exec_command(command)
        ssh_error = stderr.read().decode()
        if ssh_error:
            error(ssh_error)
            return False
        else:
            return stdout.read().decode()


def run_kubelet_cmd(k8s_ssh_conn, cmd, ns):
    try:
        if 'all-namespaces' in ns:
            namespace = ns
        else:
            namespace = "-n " + ns
        k8s_cmd = cmd + " " + namespace
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        return k8s_output.rstrip()
    except:
        error("I couldn't list pods")
        return None


def kubelet_apply(k8s_ssh_conn, cmd):
    try:
        k8s_output = run_ssh_command(k8s_ssh_conn, cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)
        return k8s_output.rstrip()
    except:
        error("I couldn't create the service account")
        return None


def create_k8s_plugin_svc_account(k8s_ssh_conn, base_url):
    try:
        k8s_cmd = "curl -s -k {} | kubectl apply -f -".format(base_url + "plugin-serviceaccount.yaml")
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)
        svc_token_cmd = "kubectl get serviceaccount pan-plugin-user -n kube-system -o jsonpath='{.secrets[0].name}'"
        svc_token = run_ssh_command(k8s_ssh_conn, svc_token_cmd)
        svc_account_json_cmd = "kubectl -n kube-system get secret {} -n kube-system -o json".format(svc_token.rstrip())
        svc_account_json = run_ssh_command(k8s_ssh_conn, svc_account_json_cmd)
        svc_account_b64 = base64.b64encode(svc_account_json.rstrip().encode()).decode()
        info("Plugin Service account base64 token generated.")
        return svc_account_b64
    except:
        error("I couldn't create the service account")
        return False


def configure_panorama(pn_ssh_conn, panorama_dict, k8s_dict):
    k8s_cluster_name = k8s_dict['k8s_cluster_name']
    k8s_cluster_ip = k8s_dict['k8s_cluster_ip']
    k8s_port = k8s_dict['k8s_port']
    k8s_type = k8s_dict['k8s_type']
    svc_acocunt_b64 = k8s_dict['svc_acocunt_b64']
    device_group = panorama_dict['device_group']
    notify_group = k8s_cluster_name + "-NG"
    monitoring_definition = k8s_cluster_name + "-MDef"
    info("Adding CN-Series license to Panorama")

    info("Configure Panorama Kubernetes plugin.")
    panorama_config_prompt = '.*# '
    with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
        interact.send('configure')
        interact.expect(panorama_config_prompt)

        info("Creating Notify Group {}".format(notify_group))
        interact.send('set plugins kubernetes setup notify-group {} '
                      'device-group {}'.format(notify_group, device_group))
        interact.expect(panorama_config_prompt)

        info("Creating kubernetes cluster {} type {}".format(k8s_cluster_name, k8s_type))
        interact.send('set plugins kubernetes setup cluster-credentials {} '
                      'labels select-all-labels'.format(k8s_cluster_name))
        interact.expect(panorama_config_prompt)
        interact.send('set plugins kubernetes setup cluster-credentials {} '
                      'cluster-credential-file service-account-cred {}'.format(k8s_cluster_name, svc_acocunt_b64))
        interact.expect(panorama_config_prompt)
        interact.send('set plugins kubernetes setup cluster-credentials {} '
                      'cluster-type {}'.format(k8s_cluster_name, k8s_type))
        interact.expect(panorama_config_prompt)
        interact.send('set plugins kubernetes setup cluster-credentials {} '
                      'api-server-address https://{}:{}'.format(k8s_cluster_name, k8s_cluster_ip, k8s_port))
        interact.expect(panorama_config_prompt)

        info("Creating monitoring definition")
        interact.send('set plugins kubernetes monitoring-definition {} '
                      'cluster-credentials {}'.format(monitoring_definition, k8s_cluster_name))
        interact.expect(panorama_config_prompt)
        interact.send('set plugins kubernetes monitoring-definition {} '
                      'notify-group {}'.format(monitoring_definition, notify_group))
        interact.expect(panorama_config_prompt)

        interact.send('exit')
        info("Panorama Configuration done, Panorama Commit is needed.")


def panorama_commit(pn_api_conn):
    try:
        info("Committing Panorama configuration.")
        commit_result = pn_api_conn.commit(sync=True)
        if commit_result['result'] == 'OK':
            info("Commit was successful")
        else:
            error("Commit Failed.")
            sys.exit()
    except:
        error("I can not commit to Panorama.")


def prettify(elem):
    """Return a pretty-printed XML string for the Element.
    """
    rough_string = ET.tostring(elem, 'utf-8')
    reparsed = parseString(rough_string)
    return reparsed.toprettyxml(indent="\t")


def main():
    """
    Command line program to configure and deploy CN-Series
    """
    fmt_str = '%(asctime)s %(levelname)s: %(message)s'

    logging_basicConfig(
        format=fmt_str, level=logging_level_INFO,
        stream=sys.stdout)

    logging_getLogger("paramiko").setLevel(logging_level_WARN)

    #
    # The default signal handler for SIGINT / CTRL-C raises a KeyboardInterrupt
    # exception which prints a possibly very long traceback. To avoid it we
    # install a custom signal handler
    #
    signal_set_handler(signal_SIGINT, custom_signal_handler)

    args = get_args()
    # Panorama info:
    pan_hostname = args.pn_ip
    pan_username = args.pn_user
    pan_password = args.pn_pass
    pan_template_stack = args.pn_tmpl
    pan_dg = args.pn_dg
    cn_auth_code = args.auth_code
    cn_tokens = args.tokens

    # Kubernetes info:
    k8s_ip = args.k8s_ip
    k8s_username = args.k8s_user
    k8s_password = args.k8s_pass
    k8s_port = args.k8s_port
    k8s_mode = args.k8s_mode
    k8s_name = args.k8s_name

    if args.k8s_type == 'native':
        k8s_type = 'Native-Kubernetes'
    elif args.k8s_type == 'openshift':
        k8s_type = 'OpenShift'
    else:
        error("Sorry I don't support this type yet. only native or openshift is supported.")
        sys.exit()

    if k8s_type == 'k8s':
        if k8s_mode == 'lite':
            yaml_base_url = K8S_BASE_URL + "lite/"
        else:
            yaml_base_url = K8S_BASE_URL + "full/"
    else:
        if k8s_mode == 'lite':
            yaml_base_url = OPENSHIFT_BASE_URL + "lite/"
        else:
            yaml_base_url = OPENSHIFT_BASE_URL + "full/"

    panorama_dict = {
        'device_group': pan_dg,
        'template_stack': pan_template_stack,
        'cn_auth_code': cn_auth_code,
        'cn_tokesn': cn_tokens
    }

    k8s_dict = {
        'k8s_cluster_name': k8s_name,
        'k8s_cluster_ip': k8s_ip,
        'k8s_port': k8s_port,
        'k8s_type': k8s_type,
        'svc_acocunt_b64': '',
        'yaml_base_url' : yaml_base_url
    }

    try:
        info("Establishing API connection with Panorama.")
        pn_api_conn = create_panos_device(pan_hostname, pan_username, pan_password)
        info("Establishing SSH connection with Panorama.")
        pn_ssh_conn = ssh_login(pan_hostname, pan_username, pan_password)
        info("Establishing SSH connection with k8s master.")
        k8s_ssh_conn = ssh_login(k8s_ip, k8s_username, k8s_password)


    except:
        print("Something went wrong, exiting...")
        sys.exit()

    panorama_version = check_panos_version(pn_api_conn)

    if int(panorama_version.split('.')[0]) >= 10:
        info("Panorama PAN-OS version is {}".format(panorama_version))
    else:
        error("Panorama PAN-OS version is {}. I need Panorama that running PAN-OS 10.0 or later, Exiting....".format(panorama_version))
        sys.exit()

    for p in range(5):
        info("checking for Kubernetes plugin.")
        k8s_plugin_version = check_k8s_plugin(pn_api_conn)
        if k8s_plugin_version:
            info("Kubernetes plugin version is {}".format(k8s_plugin_version.split('-')[1]))
            break
        else:
            error("Kubernetes plugin is not installed, I will install the latest plugin")
            info("Updating plugin list")
            update_plugin_list(pn_api_conn)

            latest_k8s = find_latest_k8s_plugin(pn_api_conn)
            if latest_k8s['name']:
                if latest_k8s['downloaded'] == 'no':
                    download_plugin(pn_ssh_conn, latest_k8s['name'])
                else:
                    info("Kubernetes plugin {} Downloaded.".format(latest_k8s['name']))
                if not wait_for_panos(pn_api_conn, time.time() + 60 * 5):
                    error("Download job taking more than expected, exiting...")
                    sys.exit()
            else:
                error("No Kubernetes plugin found. Check Panorama connection or install the plugin manually.")
                sys.exit()

            if latest_k8s['downloaded'] != 'no':
                info("Installing kubernetes plugin.")
                install_k8s_plugin(pn_ssh_conn, latest_k8s['name'])
                if not wait_for_panos(pn_api_conn, time.time() + 60 * 5):
                    error("Download job taking more than expected, exiting...")
                    sys.exit()
                info("Installation complete. I will check again if the plugin is installed properly.")
            time.sleep(10)
            panorama_commit(pn_api_conn)

    if check_device_group(pn_api_conn, pan_dg):
        info("Device group {} Found.".format(pan_dg))
    else:
        error("Device Group {} was not found in Panorama. I will add the device group to Panorama config.".format(pan_dg))
        configure_device_group(pn_ssh_conn, pan_dg)

    if check_template_stack(pn_api_conn, pan_template_stack):
        info("Template Stack {} Found.".format(pan_template_stack))
    else:
        error("Template Stack {} was not found in Panorama. "
              "I will add a Template and Template Stack to Panorama config.".format(pan_template_stack))
        configure_template(pn_ssh_conn, pan_template_stack + "-tmp")
        configure_template_stack(pn_ssh_conn, pan_template_stack)

    info("Appling CN-Series License.")
    activate_license(pn_ssh_conn, cn_auth_code, cn_tokens)

    info("Creating k8s service accout for Panorama Plugin.")
    k8s_dict['svc_acocunt_b64'] = create_k8s_plugin_svc_account(k8s_ssh_conn, yaml_base_url)
    info("Configure Panorama Plugin")
    configure_panorama(pn_ssh_conn, panorama_dict, k8s_dict)

    panorama_commit(pn_api_conn)

    # print(run_kubelet_cmd(k8s_ssh_conn, "kubectl get serviceaccount", "kube-system"))
    pn_ssh_conn.close()
    k8s_ssh_conn.close()


# Start program
if __name__ == "__main__":
    main()
