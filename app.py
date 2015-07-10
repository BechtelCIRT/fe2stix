#!bin/python

'''
    File name: app.py
    Author: Andrew Hill
    Date created: 5/28/2015
    Python Version: 2.7
    Description: REST API to parse FireEye JSON notification and generate STIX XML.
'''

# Flask imports
from flask import Flask, jsonify, request, make_response

# STIX imports
import stix.utils as utils
from cybox.core import Observable
from cybox.common import Hash
from cybox.objects.address_object import Address
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from cybox.objects.api_object import API
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.utils import set_id_namespace
from stix.data_marking import Marking, MarkingSpecification

# General imports
import json
import re

# Definitions
SAVE_DIRECTORY = "/tmp"
PRODUCER_NAME = "Bechtel Corporation"
PRODUCER_URL = "http://bechtel.com"

app = Flask(__name__)

# FireEye API Route
@app.route('/api/v1/fe', methods=['POST'])
def create_stix_file():
    # List of indicators to be deduped
    hostnames = []
    ips = []
    urls = []
    md5s = []
    sha1s = []

    # Set namespace
    NAMESPACE = { str(PRODUCER_URL) : str(PRODUCER_NAME) }
    set_id_namespace(NAMESPACE)

    # JSON load the POSTed request data
    try:
        data_recv = request.data
        data = json.loads(data_recv)
    except:
        return make_response(jsonify({'Error': "Unable to decode json object."}), 400)

    # Get MD5 of sample
    malware_sample = data['alert']['explanation']['malware-detected']['malware']
    count = 0
    sample_hash = ""

    try:
        for entry in malware_sample:
            if "md5sum" in malware_sample[count]:
                sample_hash = malware_sample[count]['md5sum']
            count += 1
    except:
        if "md5sum" in malware_sample:
            sample_hash = malware_sample['md5sum']

    # If all else fails
    if sample_hash == "":
        sample_hash = "Unknown"

    # Indicators

    # Domains
    domain_indicator = Indicator()
    domain_indicator.title = "Malware Artifacts - Domain"
    domain_indicator.type = "Malware Artifacts"
    domain_indicator.description = ("Domains derived from sandboxed malware sample.  MD5 Hash: " + sample_hash)
    domain_indicator.short_description = ("Domainss from " + sample_hash)
    domain_indicator.set_producer_identity("Bechtel Corporation")
    domain_indicator.set_produced_time(utils.dates.now())
    domain_indicator.indicator_types.append("Domain Watchlist")

    # IPs
    ip_indicator = Indicator()
    ip_indicator.title = "Malware Artifacts - IP"
    ip_indicator.description = ("IPs derived from sandboxed malware sample.  MD5 Hash: " + sample_hash)
    ip_indicator.short_description = ("IPs from " + sample_hash)
    ip_indicator.set_producer_identity("Bechtel Corporation")
    ip_indicator.set_produced_time(utils.dates.now())
    ip_indicator.indicator_types.append("IP Watchlist")

    # URLs
    url_indicator = Indicator()
    url_indicator.title = "Malware Artifacts - URL"
    url_indicator.description = ("URLs derived from sandboxed malware sample.  MD5 Hash: " + sample_hash)
    url_indicator.short_description = ("URLs from " + sample_hash)
    url_indicator.set_producer_identity("Bechtel Corporation")
    url_indicator.set_produced_time(utils.dates.now())
    url_indicator.indicator_types.append("URL Watchlist")

    # Hashs
    hash_indicator = Indicator()
    hash_indicator.title = "Malware Artifacts - File Hash"
    hash_indicator.description = ("File hashes derived from sandboxed malware sample.  MD5 Hash: " + sample_hash)
    hash_indicator.short_description = ("Hash from " + sample_hash)
    hash_indicator.set_producer_identity("Bechtel Corporation")
    hash_indicator.set_produced_time(utils.dates.now())
    hash_indicator.indicator_types.append("File Hash Watchlist")

    # Create a STIX Package
    stix_package = STIXPackage()

    # Create the STIX Header and add a description.
    stix_header = STIXHeader({"Indicators - Malware Artifacts"})
    stix_header.description = PRODUCER_NAME + ": FireEye Sample ID " + str(data['alert']['id'])
    stix_package.stix_header = stix_header

    if "network" in data['alert']['explanation']['os-changes']:
        # Add indicators for network
        for entry in data['alert']['explanation']['os-changes']['network']:
            if "hostname" in entry:
                hostnames.append(entry['hostname'])
            if "ipaddress" in entry:
                ips.append(entry['ipaddress'])
            if "http_request" in entry:
                domain = re.search('~~Host:\s(.*?)~~', entry['http_request'])
                url = re.search('^.*\s(.*?)\sHTTP', entry['http_request'])
                if domain:
                    domain_name = domain.group(1)
                if url:
                    url_string = url.group(1)
                urls.append(domain_name + url_string)

        # Add indicators for files
        for entry in data['alert']['explanation']['os-changes']['network']:
            if "md5sum" in entry['processinfo']:
                filename = re.search('([\w-]+\..*)', entry['processinfo']['imagepath'])
                if filename:
                    md5s.append((filename.group(1), entry['processinfo']['md5sum']))

    if "process" in data['alert']['explanation']['os-changes']:
        # Add indicators from process
        for entry in data['alert']['explanation']['os-changes']['process']:
            if "md5sum" in entry:
                filename = re.search('([\w-]+\..*)', entry['value'])
                if filename:
                    md5s.append((filename.group(1), entry['md5sum']))
            if "sha1sum" in entry:
                filename = re.search('([\w-]+\..*)', entry['value'])
                if filename:
                    sha1s.append((filename.group(1), entry['sha1sum']))

    # Dedupe lists
    for hostname in set(hostnames):
        hostname_observable = create_domain_name_observable(hostname)
        domain_indicator.add_observable(hostname_observable)

    for ip in set(ips):
        ip_observable = create_ipv4_observable(ip)
        ip_indicator.add_observable(ip_observable)

    for url in set(urls):
        url_observable = create_url_observable(url)
        url_indicator.add_observable(url_observable)

    for hash in set(md5s):
        hash_observable = create_file_hash_observable(hash[0], hash[1])
        hash_indicator.add_observable(hash_observable)

    for hash in set(sha1s):
        hash_observable = create_file_hash_observable(hash[0], hash[1])
        hash_indicator.add_observable(hash_observable)

    # Add those to the package
    stix_package.add(domain_indicator)
    stix_package.add(ip_indicator)
    stix_package.add(url_indicator)    
    stix_package.add(hash_indicator)

    # Save to file
    save_as = SAVE_DIRECTORY + "/fireeye_" + str(data['alert']['id']) + ".xml"
    f = open(save_as, 'w')
    f.write(stix_package.to_xml())
    f.close

    # Return success response
    return make_response(jsonify({'Success': "STIX document succesfully generated,"}), 200)

def create_ipv4_observable(ipv4_address):
    ipv4_object = Address.from_dict({'address_value': ipv4_address, 'category': Address.CAT_IPV4})
    ipv4_observable = Observable(ipv4_object)
    ipv4_observable.title = "Malware Artifact - IP"
    ipv4_observable.description = "IP derived from sandboxed malware sample."
    ipv4_observable.short_description = "IP from malware."
    return ipv4_observable

def create_domain_name_observable(domain_name):
    domain_name_object = URI.from_dict({'value': domain_name, 'type': URI.TYPE_DOMAIN})
    domain_name_observable = Observable(domain_name_object)
    domain_name_observable.title = "Malware Artifact - Domain"
    domain_name_observable.description = "Domain derived from sandboxed malware sample."
    domain_name_observable.short_description = "Domain from malware."
    return domain_name_observable

def create_file_hash_observable(filename, hash_value):
    hash_ = Hash(hash_value)
    file_ = File()
    file_.file_name = filename
    file_.add_hash(hash_)
    file_observable = Observable(file_)
    file_observable.title = "Malware Artifact - File Hash"
    file_observable.description = "File hash derived from sandboxed malware sample."
    file_observable.short_description = "File hash from malware."
    return file_observable

def create_url_observable(url):
    url_object = URI.from_dict({'value': url, 'type': URI.TYPE_URL})
    url_observable = Observable(url_object)
    url_observable.title = "Malware Artifact - URL"
    url_observable.description = "URL derived from sandboxed malware sample."
    url_observable.short_description = "URL from malware."
    return url_observable

if __name__ == '__main__':
    app.run(threaded=True, host='0.0.0.0', debug=True)

