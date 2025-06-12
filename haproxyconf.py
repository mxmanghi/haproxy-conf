#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
Script Name:     haproxyconf.py
Author:          Massimo Manghi
Date:            2025-04-23
Description:     
     Reads a file with tabular data (xls,xlxs,csv) in the format
     established to generated automatically the haproxy configuration
     for reverse proxying

Usage:
    ./haproxyconf.py --input <tabular data> 
                     --rogue <filename of rogue country codes>
                     --cidrmaps <cidr maps directory>
                     --output <output filename>

Dependencies:
    It depends on the Pandas Python library
    
Notes:
    -
==============================================================================
"""
"""
Script to generate HAProxy frontend/backend stanzas from an Excel service map,
with ACLs for Accept/Reject lists and rogue countries.
"""

import sys
import re
import logging
import pandas as pd
import os
import argparse

### ACL

class ACL:
    cidr_dir = "cidr_maps"

    def __init__(self,acl_class,acl_val,mode):
        self.acl_class  = acl_class      # either 'accept' or 'reject'
        self.mode       = mode           # 'tcp' or 'http' or 'https'
        self.val        = acl_val
        self.mode       = mode
        self.definition = ''
        self.acl_name   = ''

        if re.fullmatch(r'[A-Z]{2}',self.val):
            cidr_file = os.path.join(ACL.cidr_dir, f"{self.val}.cidr")
            acl_name = f"acl_{self.acl_class}_{self.val}"
            self.definition = f"    acl {acl_name} src -f {cidr_file}"
        elif re.fullmatch(r'\d+\.\d+\.\d+\.\d+',self.val):
            safe = self.val.replace('.','_')
            acl_name = f"acl_{self.acl_class}_ip_{safe}"
            self.definition = f"    acl {acl_name} src {self.val}"
        else:
            safe = self.val.replace('.', '_').replace('-', '_')
            acl_name = f"acl_{self.acl_class}_sni_{safe}"
            if mode in ['https','http']:
                self.definition = f"    acl {acl_name} hdr(host) -i {self.val}"
            else:
                self.definition = f"    acl {acl_name} req.ssl_sni -i {self.val}"
        self.acl_name = acl_name

    def name(self):
        return self.acl_name

    def __str__(self):
        return self.definition


### Backend

class Backend:
    def __init__(self,idx,name,mode,target_ip,target_port):
        self.idx            = idx
        self.backend_name   = f"bk_{name.replace('.','_')}_{target_ip.replace('.','_')}_{target_port}"
        self.mode           = mode
        self.target_ip      = target_ip
        self.target_port    = target_port

    def name(self):
        return self.backend_name

    def __str__(self):
        return '\n'.join([f"backend    {self.backend_name}",
                          f"    mode   {self.mode}",
                          f"    server srv{self.idx} {self.target_ip}:{self.target_port} check"])

### Frontend

class Frontend:
    def __init__(self,fename,port,mode):
        self.acl    = dict()
        self.name   = fename
        self.port   = port
        self.mode   = mode
        self.acls   = dict()

    def register_acl(self,backend,acl):
        be_name=backend.name()
        # registering acl to each backend
        # handled by this frontend
        if be_name not in self.acls:
            self.acls[be_name] = list()

        self.acls[be_name].append(acl)

    def __str__(self):

        decl_l = [f"frontend   {self.name}",
                  f"    mode   {self.mode}"]

        # let's encrypy challenge

        le_challenge_response = ["    http-request return status 200 content-type text/plain",
                                 "lf-string \"%[path,field(-1,/)].${ACCOUNT_THUMBPRINT}\\n\"",
                                 "if { path_beg '/.well-known/acme-challenge/' }"]


        if self.port == 443:
            decl_l.append(f"   bind :443 ssl crt /etc/haproxy/certs/ strict-sni")
            decl_l.append(" ".join(le_challenge_response))
        else:
            decl_l.append(f"    bind   *:{self.port}")


        declaration='\n'.join(decl_l)

        #           <declaration>
        #               acl1
        #               acl2
        #               .....
        #               acln
        #               backend route <backend1> if <acl names 1>
        #               acl1
        #               acl2
        #               .....
        #               acln
        #               backend route <backend2> if <acl names 2>

        be_acls_l = []
        for be in self.acls:
            acls = self.acls[be]
            acl_names = []
            acl_defs = []
            for acl_o in acls:
                print(f"{acl_o.name()} ---> {acl_o}")
                acl_defs.append(str(acl_o))
                acl_names.append(acl_o.name())
            print(f"acl_names {acl_names}")
            acl_names_txt = ' or '.join(acl_names)
            acl_defs.append(f"    use backend {be} if {acl_names_txt}")
            be_acls_l.append('\n'.join(acl_defs))

        return '\n'.join(["#    ------ Frontend -----", declaration,
                          "#    -------- ACLs -------", *be_acls_l])

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

service_types = {'http','pgsql','ssh'}
backends    = dict()  # list of registered backends
frontends   = dict()  # dictionary of frontends (port as key)
rogue_codes = []

def register_frontend (svctype,name,port):
    # svctype http, pgsql, ssh
    mode = 'http' if svctype == 'http' else 'tcp'
    if (port not in frontends):
        frontends[port] = Frontend(name,port,mode)

    return frontends[port]

def register_backend (idx,be_name,mode,target_ip,target_port):
    be=Backend(idx,be_name,mode,target_ip,target_port)
    be_name = be.name()
    if (be_name not in backends):
        backends[be_name] = be

    return be


def parse_list_field(field):
    """ Split Accept/Reject cell into list of entries. """
    if pd.isna(field) or not str(field).strip():
        return []
    # split on semicolon, comma, or whitespace
    return re.split(r"[;,\s]+", str(field).strip())


### main 

def main():
    parser = argparse.ArgumentParser(description='Generate HAProxy config stanzas.')
    parser.add_argument('-i','--input', default='mappa-servizi.xlsx', help='Excel file with service map')
    parser.add_argument('-r','--rogue', default='rogue.txt', help='File listing rogue country codes')
    parser.add_argument('-c','--cidrmaps', default='cidr_maps', help='Directory with country CIDR files')
    parser.add_argument('-o','--output', default='haproxy_generated.cfg', help='Output HAProxy config file')
    args = parser.parse_args()

    print(str(args))

    ACL.cidr_dir = args.cidrmaps

    fname,fext=os.path.splitext(args.input)
    
    # Read service map
    match fext:
        case ".xlsx":
            df = pd.read_excel(args.input)
        case ".csv":
            df = pd.read_csv(args.input,header=0,delimiter='|')
        case "_":
            logging.error(f"Unknown file type {fext}")
            sys.exit(1)

    # Load rogue countries
    try:
        with open(args.rogue) as f:
            for line in f:
                code = line.strip().upper()
                if code:
                    rogue_codes.append(code)
    except FileNotFoundError:
        pass

    # Start writing config
    for idx, row in df.iterrows():
        #print(f" -> {idx}: {str(row)}")

        # column 'Status' controls a service that is by default disabled
        # By putting 'enable' in this column enables the generation of its
        # configuration stanzas. A service may be therefore disabled and still
        # in the dataset for documentation or because temporarily disabled

        if (row['Status'] != "enable"):
            print(f"Service for port {row['Port']} and target IP {row['Target IP']} disabled")
            continue

        svc_type    = str(row['Service Type']).strip().lower()
        raw_sni     = row.get('SNI')
        sni         = str(raw_sni).strip() if not pd.isna(raw_sni) else ''
        
        # se sni = '' questo è un 'falsy' e quindi il nome del
        # servizio viene generato a partire dal tipo di servizio 
        # e dalla porta
        
        name = sni or f"{svc_type}_{int(row['Port'])}"

        port = int(row['Port'])
        target_ip = str(row['Target IP']).strip()
        target_port = row['Target Port']
        mode = 'http' if svc_type == 'http' else 'tcp'

        fe_name = f"srv_{svc_type}_{port}"
        fe = register_frontend(svc_type,fe_name,port)

        # register backend with the data so far collected
        be = register_backend(idx,name,mode,target_ip,target_port)

        print(f" -> {idx}: {svc_type} - {port}")

        accept_list = [x.upper() for x in parse_list_field(row.get('Accept',''))]
        reject_list = [x.upper() for x in parse_list_field(row.get('Reject',''))]

        if ('ALL' in reject_list) and ('ALL' in accept_list):
            logging.error(f"Inconsistent ACL definition for line {idx}")
            sys.exit(1)

        # Accept/Reject logic
        print(f"registering acl for service {fe.name} -> {be.name}")
        if 'ALL' in reject_list:
            # Default reject, allow only Accept list
            for val in accept_list:
                acl = ACL("accept",val,mode)
                fe.register_acl(be,acl)
        elif 'ALL' in accept_list:
            # Default allow, reject only Reject list
            for val in reject_list:
                acl = ACL("reject",val,mode)
                fe.register_acl(be,acl)

    with open(args.output, 'w') as fout:
        print("----------------")
        print("Writing backends configuration....")
        for be in backends:
            print(str(backends[be]))
            fout.write(str(backends[be])+'\n')

        print("----------------")
        print("Writing frontends configuration....")
        for fe in frontends:
            print(str(fe))
            fout.write(str(frontends[fe])+'\n')


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)

