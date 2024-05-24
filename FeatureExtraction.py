import requests

HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__
def new_HTTPResponse__init__(self, *args, **kwargs):
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        self.peercert = self._connection.sock.getpeercert()
    except AttributeError as err:
        print("new_HTTPResponse__init__ patching requests peercert error: ", err)
        pass
HTTPResponse.__init__ = new_HTTPResponse__init__

HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response
def new_HTTPAdapter_build_response(self, request, resp):
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peercert = resp.peercert
    except AttributeError as err:
        print("new_HTTPAdapter_build_response patching requests peercert error: ", err)
        pass
    return response
HTTPAdapter.build_response = new_HTTPAdapter_build_response




from urllib.parse import urlparse
def parse_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    directory = parsed_url.path.rsplit('/', 1)[0]
    file = parsed_url.path.rsplit('/', 1)[-1]
    parameters = parsed_url.query
    return domain, directory, file, parameters

def extract_features(url):
    characters = [
        ".", "-", "_", "/", "?", "=", "@", "&", "!", " ", "~", ",", "+", "*", "#", "$", "%"
    ]

    feature_counts = []
    for character in characters:
        count = url.count(character)
        feature_counts.append(count)

    return feature_counts

#Top level domain character length
from urllib.parse import urlparse
def get_tld_length(url):
    parsed_url = urlparse(url)
    tld = parsed_url.netloc.split('.')[-1]
    qty_tld_url = len(tld)
    return qty_tld_url

#Number of characters
def count_characters_in_website(url):
    length_url = len(url)
    return length_url

#Is email present
import re
def check_email_in_website(url):
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', url)
    if emails:
        email_in_url = 1
    else:
        email_in_url = 0
    return email_in_url

#Number of vowels
def qty_vowels_domain(domain):
    vowels = ['a', 'e', 'i', 'o', 'u']
    qty_vowels_domain = 0

    for char in domain.lower():
        if char in vowels:
            qty_vowels_domain += 1

    return qty_vowels_domain

#Number of domain characters
def count_characters_in_domain(domain):
    length_url = len(domain)
    return length_url

#URL domain in IP address format
def domain_in_ip(domain):
    domain_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    domain_match = re.match(domain_regex, domain)

    if domain_match:
        domain_match = 1
    else:
        domain_match = 0
    return domain_match

#'server; or 'client' in domain
def is_server_client_domain(domain):
    pattern = r'server|client'
    match = re.search(pattern, domain, re.IGNORECASE)
    if match:
        return 1
    else:
        return 0

#Number of directory characters
def count_characters_in_directory(directory):
    length_url = len(directory)
    return length_url

#Number of file name characters
def count_characters_in_file(file):
    length_url = len(file)
    return length_url

#Number of parameters characters
def count_characters_in_parameters(parameters):
    length_url = len(parameters)
    return length_url

#TLD present in parameters
def tld_present_params(parameters):
    tld_pattern = r'\.[a-zA-Z]{2,}$'
    match = re.search(tld_pattern, parameters)

    if match:
        return 1
    else:
        return 0

#Number of parameters
from urllib.parse import parse_qs

def qty_params(parameters):
    parsed_parameters = parse_qs(parameters)
    param_count = len(parsed_parameters)
    return param_count

#simulation of domain lookup time response
import time
import socket

def time_response(domain):
  start_time = time.time()
  try:
    socket.gethostbyname(domain)
  except socket.gaierror:
    return -1
  end_time = time.time()
  lookup_time = end_time - start_time
  return lookup_time

#Domain has SPF
import dns.resolver
def check_spf(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 4
        answers = resolver.resolve(domain, 'TXT')
        for answer in answers:
            if 'v=spf1' in answer.to_text():
                return 1  # SPF verification succeeded
        return 0  # SPF verification failed
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        return -1  # No answer or no TXT record is configured
    except dns.resolver.Timeout:
        return -1  # timeout
    except dns.resolver.DNSException as e:
        return -1

#ASN
from urllib.parse import urlparse
from ipwhois import IPWhois
import socket

def asn_ip(url):
  parsed_url = urlparse(url)
  hostname = parsed_url.hostname
  ip_address = socket.gethostbyname(hostname)
  obj= IPWhois(ip_address)
  result = obj.lookup_rdap()
  if 'asn' in result:
      asn = result['asn']
      return int(asn)
  else:
      return -1

#Domain activation time (in days)
import whois
from datetime import datetime
def check_domain_activation(domain):
    try:
        w = whois.whois(domain)

        if w.creation_date:
            activation_date = w.creation_date
            if len(activation_date) > 1:
                print("domain: %s finding multiple creation_date: %s" % (domain, activation_date))
                activation_date = activation_date[0]
            current_date = datetime.now()
            days_active = (current_date - activation_date).days
            return days_active
        else:
            return -1
    except whois.parser.PywhoisError:
        return -1

#Domain expiration time (in days)
import datetime as dt
def get_remaining_days(domain):
    try:
        w = whois.whois(domain)
        expiration_date = w.expiration_date

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if expiration_date:
            if isinstance(expiration_date, dt.datetime):
                remaining_days = (expiration_date.date() - dt.date.today()).days
                return remaining_days if remaining_days > 0 else 0
            elif isinstance(expiration_date, dt.date):
                remaining_days = (expiration_date - dt.date.today()).days
                return remaining_days if remaining_days > 0 else 0
            else:
                return -1
        else:
            return -1

    except whois.parser.PywhoisError:
        return -1  # 查询失败

#Number of resolved IPs
import socket

def get_ip_count(domain):
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        return len(ip_addresses)

    except socket.gaierror:
        return -1  # 域名解析失败

#Number of resolved NS
import dns.resolver

def get_resolved_ns_count(domain):
    try:
        answer = dns.resolver.resolve(domain, 'NS')
        ns_count = len(answer)
        return ns_count
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as err:
        print("domain: %s resolve NS error: %s" % (domain, err))
        return 0

#	Number of MX servers
def get_mx_count(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_count = len(answers)
        return mx_count

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as err:
        print("domain: %s resolve MX error: %s" % (domain, err))
        return 0

#TTL
def get_mx_ttl(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if mx_records:
            first_mx_record = mx_records[0]
            mx_host = first_mx_record.exchange.to_text().rstrip('.')
            mx_answers = dns.resolver.resolve(mx_host, 'A')
            if mx_answers:
                mx_ip = mx_answers[0].to_text()
                return dns.resolver.resolve(domain, 'A').rrset.ttl
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as err:
        print("domain: %s resolve MX -> A error: %s" % (domain, err))
        return 0

#Has valid TLS/SSL certificate

def check_ssl_certificate(url):
    try:
        response = requests.get(url)
        if response.ok:
            cert = response.peercert
            if cert and not cert['notAfter']:
                return 1
    except requests.exceptions.RequestException:
        pass

    return 0

#Number of redirects
def get_redirect_count(url):
    try:
        response = requests.get(url, allow_redirects=True)
        redirect_count = len(response.history)
        return redirect_count
    except requests.exceptions.RequestException:
        pass
    return 0

#Is URL indexed on Google

def check_indexed_in_google(url):
    try:
        search_url = f"https://www.google.com/search?q=site:{url}"
        response = requests.get(search_url)
        if response.ok:
            return int(url in response.text)
    except requests.exceptions.RequestException:
        pass

    return 0

#Is domain indexed on Google
def check_domain_indexed_in_google(domain):
    try:
        search_url = f"https://www.google.com/search?q=site:{domain}"
        response = requests.get(search_url)
        if response.ok:
            return int(domain in response.text)
    except requests.exceptions.RequestException:
        pass

    return 0

#Is URL shortened
def is_url_shortened(url):
    try:
        response = requests.get(url, allow_redirects=True)
        original_length = len(url)
        redirected_length = len(response.url)
        return int(original_length > redirected_length)
    except requests.exceptions.RequestException:
        pass

    return 0

def combine_result(url):
    domain, directory, file, parameters = parse_url(url)
    result=extract_features(url)+[get_tld_length(url)]+[count_characters_in_website(url)]+[check_email_in_website(url)]+extract_features(domain)+[qty_vowels_domain(domain)]+[count_characters_in_domain(domain)]+[domain_in_ip(domain)]+[is_server_client_domain(domain)]+extract_features(directory)+[count_characters_in_directory(directory)]+extract_features(file)+[count_characters_in_file(file)]+extract_features(parameters)+[count_characters_in_parameters(parameters)]+[tld_present_params(parameters)]+[qty_params(parameters)]+[time_response(domain)]+[check_spf(domain)]+[asn_ip(url)]+[check_domain_activation(domain)]+[get_remaining_days(domain)]+[get_ip_count(domain)]+[get_resolved_ns_count(domain)]+[get_mx_count(domain)]+[get_mx_ttl(domain)]+[check_ssl_certificate(url)]+[get_redirect_count(url)]+[check_indexed_in_google(url)]+[check_domain_indexed_in_google(domain)]+[is_url_shortened(url)]
    return result

import pandas as pd
def reformat(url):
    features = combine_result(url)
    column_names = ['qty_dot_url', 'qty_hyphen_url', 'qty_underline_url', 'qty_slash_url', 'qty_questionmark_url',
                'qty_equal_url', 'qty_at_url', 'qty_and_url', 'qty_exclamation_url', 'qty_space_url',
                'qty_tilde_url', 'qty_comma_url', 'qty_plus_url', 'qty_asterisk_url', 'qty_hashtag_url',
                'qty_dollar_url', 'qty_percent_url', 'qty_tld_url', 'length_url', 'qty_dot_domain',
                'qty_hyphen_domain', 'qty_underline_domain', 'qty_slash_domain', 'qty_questionmark_domain',
                'qty_equal_domain', 'qty_at_domain', 'qty_and_domain', 'qty_exclamation_domain',
                'qty_space_domain', 'qty_tilde_domain', 'qty_comma_domain', 'qty_plus_domain',
                'qty_asterisk_domain', 'qty_hashtag_domain', 'qty_dollar_domain', 'qty_percent_domain',
                'qty_vowels_domain', 'domain_length', 'domain_in_ip', 'server_client_domain',
                'qty_dot_directory', 'qty_hyphen_directory', 'qty_underline_directory', 'qty_slash_directory',
                'qty_questionmark_directory', 'qty_equal_directory', 'qty_at_directory', 'qty_and_directory',
                'qty_exclamation_directory', 'qty_space_directory', 'qty_tilde_directory', 'qty_comma_directory',
                'qty_plus_directory', 'qty_asterisk_directory', 'qty_hashtag_directory', 'qty_dollar_directory',
                'qty_percent_directory', 'directory_length', 'qty_dot_file', 'qty_hyphen_file', 'qty_underline_file',
                'qty_slash_file', 'qty_questionmark_file', 'qty_equal_file', 'qty_at_file', 'qty_and_file',
                'qty_exclamation_file', 'qty_space_file', 'qty_tilde_file', 'qty_comma_file', 'qty_plus_file',
                'qty_asterisk_file', 'qty_hashtag_file', 'qty_dollar_file', 'qty_percent_file', 'file_length',
                'qty_dot_params', 'qty_hyphen_params', 'qty_underline_params', 'qty_slash_params',
                'qty_questionmark_params', 'qty_equal_params', 'qty_at_params', 'qty_and_params',
                'qty_exclamation_params', 'qty_space_params', 'qty_tilde_params', 'qty_comma_params',
                'qty_plus_params', 'qty_asterisk_params', 'qty_hashtag_params', 'qty_dollar_params',
                'qty_percent_params', 'params_length', 'tld_present_params', 'qty_params', 'email_in_url',
                'time_response', 'domain_spf', 'asn_ip', 'time_domain_activation', 'time_domain_expiration',
                'qty_ip_resolved', 'qty_nameservers', 'qty_mx_servers', 'ttl_hostname', 'tls_ssl_certificate',
                'qty_redirects', 'url_google_index', 'domain_google_index', 'url_shortened']
    print("url: %s column_names length: %s" % (url, len(column_names)))
    df = pd.DataFrame(columns=column_names)

    df.loc[0] = features
    df = df.astype('int')
    df['time_response'] = df['time_response'].astype('float')
    return df

import joblib
import pandas as pd
import pickle
def pca(url):
    scaler = joblib.load('pkl/scaler.pkl')
    pca = joblib.load('pkl/pca.pkl')
    selected_features = joblib.load('pkl/selected_features.pkl')
    new_data = reformat(url)
    new_data_scaled = scaler.transform(new_data)
    new_data_scaled = pd.DataFrame(new_data_scaled, columns=new_data.columns)
    new_data_selected = new_data_scaled[selected_features]
    new_data_pca = pca.transform(new_data_selected)
    return new_data_pca
