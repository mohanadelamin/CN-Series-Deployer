## CN-Series Deployer
Python script to deploy Palo Alto Networks [CN-Series](https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-new-features/virtualization-features/cn-series-firewalls-for-securing-kubernetes-deployments.html) in Kubernetes **Native** or **OpenShift**.

The script will do the following tasks:
1. Check Panorama PAN-OS version and confirm its running version 10.0 or later.
2. Check Panorama if kubernetes plugin is installed. If not, the script will download and install the latest kubernetes plugin.
3. Check Panorama if the following is configured. If not, the script will add them to Panorama config.
    - Device Group.
    - Template Stack.
    - Log Collector Group
    
4. Add a service account to K8S. The service account to be used by the Panorama Plugin.
5. Configure Panorama plugin. And apply the license for the CN-Series.
6- Deploy the following on the k8s cluster:
    - Service accounts for CN-CNI and CN-MGMT.
    - Config map for CN-CNI, CN-MGMT, and CN-NGFW.
    - CN-CNI DaemonSet
    - CN-MGMT StatefulSet
    - CN-NGFW DaemonSet.

## Prerequisites

The best way to run this script is using [Panhandler](https://live.paloaltonetworks.com/t5/skillet-tools/install-and-get-started-with-panhandler/ta-p/307916).

To run the script directly then you will need:
1. Python3
2. The following python modules (can be installed using: pip3 install -r requirements.txt)
    - pandevice==0.10.0
    - paramiko==2.7.1
    - paramiko-expect==0.2.8

## Usage

1. Import the repo into your panhandler
2. Run the skillet and fill the required fields and click submit (Make sure to add quotes if the value will contain space):
3. Wait for the skillet to download the required Python modules (pandevice, paramiko, and paramiko-expect).
4. Finally the skillet will deploy the CN-Series and configure Panorama.  


**Note: At the moment the script will need to run the kubectl commands from another host, that host can either be the master node it self or another linux machine with kubectl or oc installed on it. In future versions the script will use kubernetes API directly.**



Check the following video for example deployment:

[![Demo](https://img.youtube.com/vi/gX2NhC4kpwM/hqdefault.jpg)](https://youtu.be/gX2NhC4kpwM)



To test the CN-Series you can use the following example [app](https://github.com/mohanadelamin/yelb):
```
$ kubectl create namespace yelb
$ kubectl annotate namespace yelb paloaltonetworks.com/firewall=pan-fw
$ curl -s -k https://raw.githubusercontent.com/mohanadelamin/yelb/master/yelb.yaml | kubectl apply -f -
```


## Support Policy ##

The code and templates in the repo are released under an as-is, best effort,
support policy. These scripts should be seen as community supported and
Palo Alto Networks will contribute our expertise as and when possible.
We do not provide technical support or help in using or troubleshooting the
components of the project through our normal support options such as
Palo Alto Networks support teams, or ASC (Authorized Support Centers)
partners and backline support options. The underlying product used
(the VM-Series firewall) by the scripts or templates are still supported,
but the support is only for the product functionality and not for help in
deploying or using the template or script itself. Unless explicitly tagged,
all projects or work posted in our GitHub repository
(at https://github.com/PaloAltoNetworks) or sites other than our official
Downloads page on https://support.paloaltonetworks.com are provided under
