#!/usr/bin/env python3
# CN-Series-Deployer is a script to deploy Palo Alto Networks CN-Series.
#
# Authored by Mohanad Elamin (melamin@paloaltonetworks.com)
#
# The script will do the following:




__author__ = "Mohanad Elamin @mohanadelamin"
__version__ = "2.0"
__license__ = "MIT"

import sys
import argparse
import re
import gzip
import io
import time
import base64
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


BASE_URL = 'https://raw.githubusercontent.com/PaloAltoNetworks/Kubernetes/master/'


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
    parser.add_argument('--pn_ip', required=True,
                        action='store', help='Panorama management IP address')
    parser.add_argument('--pn_user', required=True,
                        action='store', help='Panorama username')
    parser.add_argument('--pn_pass', required=True,
                        action='store', help='Panorama Password')
    parser.add_argument('--ctl_ip', required=True,
                        action='store', help='Kubectl or oc node IP address')
    parser.add_argument('--k8s_ip', required=True,
                        action='store', help='K8S master node IP address')
    parser.add_argument('--k8s_user', required=True,
                        action='store', help='Panorama username')
    parser.add_argument('--k8s_pass', required=True,
                        action='store', help='Panorama Password')
    parser.add_argument('--k8s_type', required=True,
                        action='store', default='k8s', help='Cluster Type, k8s native or openshift.')
    parser.add_argument('--k8s_port', required=True,
                        action='store', default='6443', help='k8s port, default 6443')
    parser.add_argument('--k8s_mode', required=True,
                        action='store', default='lite', help='deployment mode. lite or full')
    parser.add_argument('--k8s_name', required=True,
                        action='store', help='K8S Cluster name')
    parser.add_argument('--pn_dg', required=True,
                        action='store', help='Panorama device group')
    parser.add_argument('--pn_tmpl', required=True,
                        action='store', help='Panorama Collector Group')
    parser.add_argument('--pn_cg', required=True,
                        action='store', help='Panorama device group')
    parser.add_argument('--auth_code', required=True,
                        action='store', help='CN-Series Auth_code')
    parser.add_argument('--cn_bnd', required=True,
                        action='store', help='CN-Series bundle')
    parser.add_argument('--tokens', required=True, default=1,
                        action='store', help='Number of CN-Series tokens.')
    parser.add_argument('--cn_mgmt_image', required=True,
                        action='store', help='CN-MGMT Image registry path')
    parser.add_argument('--cn_ngfw_image', required=True,
                        action='store', help='CN-NGFW Image registry path')
    parser.add_argument('--cn_init_image', required=True,
                        action='store', help='CN-MGMT init Image registry path')
    parser.add_argument('--cn_cni_image', required=True,
                        action='store', help='CNI Image registry path')
    parser.add_argument('--cn_pin_id', required=False,
                        action='store', help='CN-Series registration pin id')
    parser.add_argument('--cn_pin_value', required=False,
                        action='store', help='CN-Series registration pin value')
    parser.add_argument('--pv_type', required=False,
                        action='store', help='CN-MGMT Persistent Volumes type: Manual, Local, or Dynamic')

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
        return False
    except SSH_AuthenticationException:
        error("SSH authentication failed for {}".format(host))
        return False
    except SSH_SSHException as errstr:
        error("Unknown SSH error while connecting to {0}: {1}".format(host, errstr))
        return False
    except OSError as err:
        error("Can't connect to SSH server {0}: '{1}'".format(host, err))
        return False
    except:
        error("Unknown error encountered while connecting to SSH server {}".format(host))
        return False

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
    info("Checking if PAN-OS is ready to accept requests.")
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


def check_collector_group(pn_api_conn, cg):
    try:
        element_response = pn_api_conn.op(cmd="show log-collector-group all")
    except PanDeviceError as msg:
        error(msg)
        time.sleep(5)
    else:
        device_groups = element_response.findall('.//entry')
        for n in device_groups:
            if cg == n.attrib['name']:
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
    try:
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
    except:
        error("I can not create a template")
        sys.exit()


def configure_template_stack(pn_ssh_conn, template_stack):
    try:
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
    except:
        error("I can not create a template stack")
        sys.exit()


def configure_device_group(pn_ssh_conn, dg):
    try:
        panorama_config_prompt = '.*# '
        with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
            interact.send('configure')
            interact.expect(panorama_config_prompt)
            interact.send('set device-group {}'.format(dg))
            interact.expect(panorama_config_prompt)
            interact.send('exit')
    except:
        error("I can not create a device group")
        sys.exit()


def configure_collector_group(pn_ssh_conn, cg):
    try:
        panorama_config_prompt = '.*# '
        with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
            interact.send('configure')
            interact.expect(panorama_config_prompt)
            interact.send('set log-collector-group {}'.format(cg))
            interact.expect(panorama_config_prompt)
            interact.send('exit')
    except:
        error("I can not create a device group")
        sys.exit()


def create_auth_key(pn_ssh_conn):
    try:
        duration = 48
        panorama_op_prompt = '.*> '
        with SSHClientInteraction(pn_ssh_conn, timeout=10, display=False) as interact:
            interact.send("request bootstrap vm-auth-key generate lifetime {}".format(duration))
            interact.expect(panorama_op_prompt)
            interact.send('exit')
        auth_key_output = interact.current_output_clean
        for l in auth_key_output.split('\n'):
            if 'generated' in l:
                auth_key = re.findall(r"\d{15,}", l)[0]
                return auth_key.strip()
    except:
        error("I couldn't create bootstrapping auth key")
        sys.exit()


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
            info("Plugin {} installation triggered".format(plugin))
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


def gzip_str(string_):
    out = io.BytesIO()

    with gzip.GzipFile(fileobj=out, mode='w') as fo:
        fo.write(string_.encode())

    bytes_obj = out.getvalue()
    return bytes_obj


def create_k8s_plugin_svc_account(k8s_ssh_conn, base_url, ctl):
    try:
        k8s_cmd = "curl -s -k {} | {} apply -f -".format(base_url + "plugin-serviceaccount.yaml", ctl)
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)
        svc_token_cmd = ctl + " get serviceaccount pan-plugin-user -n kube-system " \
                              "-o jsonpath='{range .secrets[*]}{.name}{\"\\n\"}' " \
                              "| grep -m1 -oP \".*token.*\" " \
                              "| tr -d \"\\012\\015\""
        svc_token = run_ssh_command(k8s_ssh_conn, svc_token_cmd)
        svc_account_json_cmd = "{} -n kube-system get secret {} -n kube-system -o json".format(ctl, svc_token.rstrip())
        svc_account_json = run_ssh_command(k8s_ssh_conn, svc_account_json_cmd)
        svc_account_gzip = gzip_str(svc_account_json.rstrip())
        svc_account_b64 = base64.b64encode(svc_account_gzip).decode()
        info("Plugin Service account base64 token generated.")
        return svc_account_b64
    except:
        error("I couldn't create the service account")
        sys.exit()


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


def create_cn_series(k8s_ssh_conn, base_url, cn_images_dict, panorama_dict, k8s_dict):
    try:
        replicas = '1' if k8s_dict['k8s_mode'] == 'lite' else '2'

        ctl = k8s_dict['ctl']
        info("Creating CN-CNI account.")
        k8s_cmd = "curl -s -k {} | {} apply -f -".format(base_url + "pan-cni-serviceaccount.yaml", ctl)
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)

        info("Creating CN-MGMT service account.")
        k8s_cmd = "curl -s -k {} | {} apply -f -".format(base_url + "pan-mgmt-serviceaccount.yaml", ctl)
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)

        info("Creating CN-CNI config map.")
        k8s_cmd = "curl -s -k {} | {} apply -f -".format(base_url + "pan-cni-configmap.yaml", ctl)
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)

        info("Creating CN-CNI pods.")
        k8s_cmd = "curl -s -k {} " \
                  "| sed 's/k8s-app/app/g'" \
                  "| sed 's/<your-private-registry-image-path>/{}/g' " \
                  "| {} apply -f -".format(base_url + "pan-cni.yaml",
                                           cn_images_dict['cn_cni_image'].replace('/','\/'),
                                           ctl)
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)

        if k8s_dict['cn_pin_id'] and k8s_dict['cn_pin_value']:
            info("Creating CN-MGMT secret")
            k8s_cmd = "curl -s -k {} " \
                      "| sed 's/<panorama-auth-key>/{}/g' " \
                      "| sed 's/<PIN Id>/{}/g' " \
                      "| sed 's/<PIN-Value>/{}/g' " \
                      "| {} apply -f -".format(base_url + "pan-cn-mgmt-secret.yaml",
                                               panorama_dict['auth_key'],
                                               k8s_dict['cn_pin_id'],
                                               k8s_dict['cn_pin_value'],
                                               ctl)
            k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
            for l in k8s_output.rstrip().split('\n'):
                info(l)
        else:
            info("Creating CN-MGMT secret")
            info("Commenting CN-Series auto registration pin id and value lines.")
            k8s_cmd = "curl -s -k {} " \
                      "| sed 's/<panorama-auth-key>/{}/g' " \
                      "| sed '/.*CN-SERIES-AUTO-REGISTRATION-PIN.*/s/^/#/g' " \
                      "| {} apply -f -".format(base_url + "pan-cn-mgmt-secret.yaml",
                                               panorama_dict['auth_key'],
                                               ctl)
            k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
            for l in k8s_output.rstrip().split('\n'):
                info(l)

        info("Creating CN-MGMT config map")
        k8s_cmd = "curl -s -k {} " \
                  "| sed 's/<panorama-IP>/{}/g' " \
                  "| sed 's/<panorama-device-group>/{}/g' "\
                  "| sed 's/<panorama-template-stack>/{}/g' " \
                  "| sed 's/<panorama-collector-group>/{}/g' " \
                  "| sed 's/<license-bundle-type>/{}/g' " \
                  "| {} apply -f -".format(base_url + "pan-cn-mgmt-configmap.yaml",
                                           panorama_dict['pan_hostname'],
                                           panorama_dict['device_group'],
                                           panorama_dict['template_stack'],
                                           panorama_dict['c_group'],
                                           panorama_dict['cn_bundle'],
                                           ctl)
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)

        if k8s_dict['k8s_type'] == 'Native-Kubernetes':
            if k8s_dict['pv_type'] == "manual":
                info("Creating manual PVs for CN-MGMT Pods")
                k8s_cmd = "curl -s -k {} | {} apply -f -".format(base_url + "pan-cn-pv-manual.yaml", ctl)
                k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
                for l in k8s_output.rstrip().split('\n'):
                    info(l)

                info("Creating CN-MGMT pods.")
                info("Selected mode is {}. I will deploy {} replica(s)".format(k8s_dict['k8s_mode'], replicas))
                k8s_cmd = "curl -s -k {} " \
                          "| sed 's/replicas: .*$/replicas: {}/' " \
                          "| sed '0,/<your-private-registry-image-path>/s/<your-private-registry-image-path>/{}/' " \
                          "| sed '0,/<your-private-registry-image-path>/s/<your-private-registry-image-path>/{}/' " \
                          "| sed 's/pan-local-storage/manual/g' " \
                          "| {} apply -f -".format(base_url + "pan-cn-mgmt.yaml",
                                                   replicas,
                                                   cn_images_dict['cn_init_image'].replace('/','\/'),
                                                   cn_images_dict['cn_mgmt_image'].replace('/','\/'),
                                                   ctl)
                k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
                for l in k8s_output.rstrip().split('\n'):
                    info(l)

            elif k8s_dict['pv_type'] == "local":
                info("Creating local PVs for CN-MGMT Pods")
                k8s_cmd = "curl -s -k {} | {} apply -f -".format(base_url + "pan-cn-pv-local.yaml", ctl)
                k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
                for l in k8s_output.rstrip().split('\n'):
                    info(l)

                info("Creating CN-MGMT pods.")
                info("Selected mode is {}. I will deploy {} replica(s)".format(k8s_dict['k8s_mode'], replicas))
                k8s_cmd = "curl -s -k {} " \
                          "| sed 's/replicas: .*$/replicas: {}/' " \
                          "| sed '0,/<your-private-registry-image-path>/s/<your-private-registry-image-path>/{}/' " \
                          "| sed '0,/<your-private-registry-image-path>/s/<your-private-registry-image-path>/{}/' " \
                          "| {} apply -f -".format(base_url + "pan-cn-mgmt.yaml",
                                                   replicas,
                                                   cn_images_dict['cn_init_image'].replace('/','\/'),
                                                   cn_images_dict['cn_mgmt_image'].replace('/','\/'),
                                                   ctl)
                k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
                for l in k8s_output.rstrip().split('\n'):
                    info(l)

            else:
                info("Creating CN-MGMT pods.")
                info("Selected mode is {}. I will deploy {} replica(s)".format(k8s_dict['k8s_mode'], replicas))
                k8s_cmd = "curl -s -k {} " \
                          "| sed 's/replicas: .*$/replicas: {}/' " \
                          "| sed '0,/<your-private-registry-image-path>/s/<your-private-registry-image-path>/{}/' " \
                          "| sed '0,/<your-private-registry-image-path>/s/<your-private-registry-image-path>/{}/' " \
                          "| sed 's/storageClassName/#storageClassName/g' " \
                          "| {} apply -f -".format(base_url + "pan-cn-mgmt.yaml",
                                                   replicas,
                                                   cn_images_dict['cn_init_image'].replace('/', '\/'),
                                                   cn_images_dict['cn_mgmt_image'].replace('/', '\/'),
                                                   ctl)
                k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
                for l in k8s_output.rstrip().split('\n'):
                    info(l)

        else:
            info("Creating CN-MGMT pods.")
            info("Selected mode is {}. I will deploy {} replica(s)".format(k8s_dict['k8s_mode'], replicas))
            k8s_cmd = "curl -s -k {} " \
                      "| sed 's/replicas: .*$/replicas: {}/' " \
                      "| sed '0,/<your-private-registry-image-path>/s/<your-private-registry-image-path>/{}/' " \
                      "| sed '0,/<your-private-registry-image-path>/s/<your-private-registry-image-path>/{}/' " \
                      "| {} apply -f -".format(base_url + "pan-cn-mgmt.yaml",
                                               replicas,
                                               cn_images_dict['cn_init_image'].replace('/', '\/'),
                                               cn_images_dict['cn_mgmt_image'].replace('/', '\/'),
                                               ctl)
            k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
            for l in k8s_output.rstrip().split('\n'):
                info(l)

        info("Creating CN-NGFW config map.")
        k8s_cmd = "curl -s -k {} | {} apply -f -".format(base_url + "pan-cn-ngfw-configmap.yaml", ctl)
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)

        info("Creating CN-NGFW pods.")
        k8s_cmd = "curl -s -k {} " \
                  "| sed 's/<your-private-registry-image-path>/{}/g' " \
                  "| {} apply -f -".format(base_url + "pan-cn-ngfw.yaml",
                                                cn_images_dict['cn_ngfw_image'].replace('/','\/'), ctl)
        k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
        for l in k8s_output.rstrip().split('\n'):
            info(l)

        return True
    except:
        error("CN-Series deployment fails.")
        sys.exit()


def check_pods_status(k8s_ssh_conn, ctl):
    all_running = True
    info("Checking if pods are running.")
    k8s_cmd = ctl + " get pods -n kube-system -l 'app in ( pan-mgmt, pan-ngfw, pan-cni)' " \
                    "-o jsonpath='{range .items[*]}{@.metadata.name}{\"=\"}{@.status.phase}{\",\"}{end}'"
    k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
    for l in k8s_output.rstrip().split(',')[:-1]:
        info("Pod: {: <20} status is {}".format(l.split('=')[0], l.split('=')[1]))
        if 'running' not in l.lower():
            all_running = False
    return all_running


def check_container_status(k8s_ssh_conn, ctl):
    all_ready = True
    info("Checking if containers are ready.")
    k8s_cmd = ctl + " get pods -n kube-system -l 'app in ( pan-mgmt, pan-ngfw, pan-cni)' " \
                    "-o jsonpath='{range .items[*]}{@.metadata.name}" \
                    "{\"=\"}{@.status.initContainerStatuses[*].name}" \
                    "{\"=\"}{@.status.initContainerStatuses[*].ready}" \
                    "{\",\"}{@.metadata.name}{\"=\"}" \
                    "{@.status.containerStatuses[*].name}" \
                    "{\"=\"}{@.status.containerStatuses[*].ready}" \
                    "{\",\"}{end}'"
    k8s_output = run_ssh_command(k8s_ssh_conn, k8s_cmd)
    for l in k8s_output.rstrip().split(',')[:-1]:
        if l.split('=')[1] == '':
            continue
        pod_name = l.split('=')[0]
        con_name = l.split('=')[1]
        con_status = "Ready" if l.split('=')[2] == 'true' else "Not Ready"
        info("Pod: {: <20} Container: {: <20} status: {}".format(pod_name, con_name, con_status))
        if 'true' not in l.lower():
            all_ready = False
    return all_ready


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
    try:
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
        pan_cg = args.pn_cg
        cn_auth_code = args.auth_code
        cn_tokens = args.tokens
        cn_bundle = args.cn_bnd

        # Kubernetes info:
        k8s_ip = args.k8s_ip
        ctl_ip = args.ctl_ip
        k8s_username = args.k8s_user
        k8s_password = args.k8s_pass
        k8s_port = args.k8s_port
        if args.k8s_mode == 'lite' or args.k8s_mode == 'full':
            k8s_mode = args.k8s_mode
        else:
            error("Sorry I don't support this mode. Only lite or full are supported.")
            sys.exit()
        k8s_name = args.k8s_name

        pv_type = args.pv_type

        cn_pin_id = args.cn_pin_id
        cn_pin_value = args.cn_pin_value

        if not cn_pin_id or not cn_pin_value:
            if k8s_mode == 'full':
                error("You selected full mode. CN Series registration pin id and value is required.")
                sys.exit()

        if args.k8s_type == 'native':
            k8s_type = 'Native-Kubernetes'
        elif args.k8s_type == 'openshift':
            k8s_type = 'OpenShift'
        else:
            error("Sorry I don't support this type yet. only native or openshift is supported.")
            sys.exit()

        if k8s_type == 'Native-Kubernetes':
            yaml_base_url = BASE_URL + "native/"
            if not pv_type:
                error("PV Type is required for Native deployment.")
                sys.exit()
        elif k8s_type == 'OpenShift':
            yaml_base_url = BASE_URL + "openshift/"

        ctl = 'kubectl' if k8s_type == 'Native-Kubernetes' else 'oc'

        cn_images_dict = {
            'cn_mgmt_image': args.cn_mgmt_image,
            'cn_ngfw_image': args.cn_ngfw_image,
            'cn_init_image': args.cn_init_image,
            'cn_cni_image': args.cn_cni_image
        }

        panorama_dict = {
            'pan_hostname': pan_hostname,
            'pan_username': pan_username,
            'pan_password': pan_password,
            'device_group': pan_dg,
            'template_stack': pan_template_stack,
            'cn_auth_code': cn_auth_code,
            'cn_tokens': cn_tokens,
            'c_group': pan_cg,
            'cn_bundle': cn_bundle,
            'auth_key': ''
        }

        k8s_dict = {
            'k8s_cluster_name': k8s_name,
            'ctl_ip': ctl_ip,
            'k8s_cluster_ip': k8s_ip,
            'k8s_port': k8s_port,
            'k8s_type': k8s_type,
            'svc_acocunt_b64': '',
            'yaml_base_url' : yaml_base_url,
            'k8s_mode': k8s_mode,
            'pv_type': pv_type,
            'cn_pin_id': cn_pin_id,
            'cn_pin_value': cn_pin_value,
            'ctl': ctl
        }

        try:
            info("Establishing API connection with Panorama.")
            pn_api_conn = create_panos_device(pan_hostname, pan_username, pan_password)
            info("Establishing SSH connection with Panorama.")
            pn_ssh_conn = ssh_login(pan_hostname, pan_username, pan_password)
            info("Establishing SSH connection with k8s master.")
            k8s_ssh_conn = ssh_login(ctl_ip, k8s_username, k8s_password)
            if not (pn_api_conn and pn_ssh_conn and k8s_ssh_conn):
                info("Without connection to both the kubernetes cluster and Panorama I can not work.")
                sys.exit()
        except:
            error("Something went wrong which establishing connection, exiting...")
            sys.exit()

        panorama_version = check_panos_version(pn_api_conn)

        if int(panorama_version.split('.')[0]) >= 10:
            info("Panorama PAN-OS version is {}".format(panorama_version))
        else:
            error("Panorama PAN-OS version is {}. I need Panorama that running PAN-OS 10.0 or later, Exiting....".format(panorama_version))
            sys.exit()

        commit_required = False

        info("checking for Kubernetes plugin.")
        k8s_plugin_version = check_k8s_plugin(pn_api_conn)
        if k8s_plugin_version:
            info("Kubernetes plugin version is {}".format(k8s_plugin_version.split('-')[1]))
        else:
            error("Kubernetes plugin is not installed, I will install the latest plugin")
            info("Updating plugin list")
            update_plugin_list(pn_api_conn)

            for p in range(3):
                latest_k8s = find_latest_k8s_plugin(pn_api_conn)
                if latest_k8s['name']:
                    if latest_k8s['downloaded'] == 'no':
                        download_plugin(pn_ssh_conn, latest_k8s['name'])
                    else:
                        info("Kubernetes plugin {} Downloaded.".format(latest_k8s['name']))
                        break
                    if not wait_for_panos(pn_api_conn, time.time() + 60 * 5):
                        error("Download job taking more than expected, exiting...")
                        sys.exit()
                    # Give the download some time
                    time.sleep(10)
                else:
                    error("No Kubernetes plugin found. Check Panorama connection or install the plugin manually.")
                    sys.exit()
                info("Checking if plugin is downloaded properly.")

            for p in range(3):
                if latest_k8s['downloaded'] != 'no':
                    info("Installing kubernetes plugin.")
                    install_k8s_plugin(pn_ssh_conn, latest_k8s['name'])
                    commit_required = True
                    if not wait_for_panos(pn_api_conn, time.time() + 60 * 5):
                        error("Download job taking more than expected, exiting...")
                        sys.exit()
                    info("Installation complete. I will check again if the plugin is installed properly.")
                    # Give the install some time
                    time.sleep(10)
                    k8s_plugin_version = check_k8s_plugin(pn_api_conn)
                    if k8s_plugin_version:
                        info("Kubernetes plugin version is {}".format(k8s_plugin_version.split('-')[1]))
                        break
                    else:
                        info("Plugin installation was not successful I will try again.")
                else:
                    info("Plugin is not installed, exiting.")
                    sys.exit()

        if commit_required:
            info("Committing configuration")
            panorama_commit(pn_api_conn)

        if check_device_group(pn_api_conn, pan_dg):
            info("Device group {} Found.".format(pan_dg))
        else:
            error("Device Group {} was not found in Panorama. "
                  "I will add the device group to Panorama config.".format(pan_dg))
            configure_device_group(pn_ssh_conn, pan_dg)

        if check_template_stack(pn_api_conn, pan_template_stack):
            info("Template Stack {} Found.".format(pan_template_stack))
        else:
            error("Template Stack {} was not found in Panorama. "
                  "I will add a Template and Template Stack to Panorama config.".format(pan_template_stack))
            configure_template(pn_ssh_conn, pan_template_stack + "-tmp")
            configure_template_stack(pn_ssh_conn, pan_template_stack)

        if check_collector_group(pn_api_conn, pan_cg):
            info("Collector group {} found.".format(pan_cg))
        else:
            info("Collector group {} not found. "
                 "I will add a dummy one you can add log collector to it later.".format(pan_cg))
            configure_collector_group(pn_ssh_conn, pan_cg)

        info("Applying CN-Series License.")

        activate_license(pn_ssh_conn, panorama_dict['cn_auth_code'], panorama_dict['cn_tokens'])

        info("Creating k8s service account for Panorama Plugin.")
        k8s_dict['svc_acocunt_b64'] = create_k8s_plugin_svc_account(k8s_ssh_conn, yaml_base_url, ctl)
        info("Configure Panorama Plugin")
        configure_panorama(pn_ssh_conn, panorama_dict, k8s_dict)

        info("Creating bootstrapping authentication key")
        panorama_dict['auth_key'] = create_auth_key(pn_ssh_conn)

        # Committing changes to Panorama.
        panorama_commit(pn_api_conn)

        info("Deploying CN-Series")
        if create_cn_series(k8s_ssh_conn, yaml_base_url, cn_images_dict, panorama_dict, k8s_dict):
            info("CN-Series is deployed successfully.")
            info("Depending on the image download speed, it will take some time to pull images and finish deployment.")
            info("")
            info("=======================================================================================================")
            info("")
            info("I AM DONE! You can now monitor the CN-Series deployment using the following command from the k8s master")
            info("")
            info("kubectl get pods -n kube-system")
            info("")
            info("")
            info("The script will keep checking for the pods status every 5 min. Installation will take about 15 min.")
            info("You can exit now and monitor manually if you prefer")
            info("=======================================================================================================")
            info("")
            info("")

        info("I will sleep for 5 min then I will start checking the pods status.")
        time.sleep(300)

        success = False
        for c_pod in range(6):
            if check_pods_status(k8s_ssh_conn, ctl):
                info("All pods are running. I will now check if all containers are ready.")
                for c_c in range(6):
                    if check_container_status(k8s_ssh_conn, ctl):
                       info("All containers are ready.")
                       success = True
                       break
                    else:
                       info("Not all containers are ready. I will check again after 5 min.")
                       time.sleep(300)
                break
            else:
                info("Not all pods are running. I will check again after 5 min.")
                time.sleep(300)

        if success:
            info("*******************************************************************************************************")
            info("")
            info("")
            info("Installation done successfully.")
            info("")
            info("")
            info("*******************************************************************************************************")
        else:
            error("Seem like there is some errors during deployment. Please log in the k8s cluster and check the status.")

        pn_ssh_conn.close()
        k8s_ssh_conn.close()
    except:
        error("An error occurred that I couldn't handle!")


# Start program
if __name__ == "__main__":
    main()
