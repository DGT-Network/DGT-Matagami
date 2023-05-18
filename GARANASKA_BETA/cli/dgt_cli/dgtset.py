# Copyright 2020 DGT NETWORK INC © Stanislav Parsov 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

import argparse
from base64 import b64decode
import csv
import getpass
import hashlib
import json
import logging
import os
import sys
import traceback
import random
import yaml
import time
import pkg_resources
from os.path import exists
from colorlog import ColoredFormatter
from dgt_cli.parent_parsers import base_http_parser
from dgt_cli.exceptions import CliException
from dgt_cli.rest_client import RestClient
from dgt_cli.make_set_txn import _create_batch,_create_propose_txn,_create_topology_txn,_create_vote_txn,_key_to_address


from dgt_sdk.protobuf.settings_pb2 import SettingCandidates
#from dgt_cli.protobuf.settings_pb2 import SettingCandidates
#from dgt_cli.protobuf.setting_pb2 import Setting
from dgt_validator.protobuf.setting_pb2 import Setting

#from dgt_cli.protobuf.transaction_pb2 import TransactionHeader
#from dgt_cli.protobuf.transaction_pb2 import Transaction

from dgt_validator.protobuf.batch_pb2 import BatchList
#from dgt_cli.protobuf.batch_pb2 import BatchList

from dgt_signing import create_context
from dgt_signing import CryptoFactory,key_to_dgt_addr
from dgt_signing import ParseError
from dgt_validator.gossip.fbft_topology import (PeerSync,PeerRole,PeerAtr,FbftTopology,TOPOLOGY_SET_NM,DGT_PING_COUNTER,
                                                DGT_TOPOLOGY_SET_NM,DGT_TOPOLOGY_MAP_NM,DGT_TOPOLOGY_NEST_NM,TOPO_MAP,TOPO_GATES,DGT_NET_NEST
                                                )

from x509_cert.client_cli.xcert_attr import XCERT_CRT_OP,NOTARY_LIST_ID,NOTARY_KEYS,NOTARIES_MAP,DGT_NOTARY_KEYS
from x509_cert.client_cli.create_batch import create_meta_xcert_txn


DGT_TOP = os.environ.get('DGT_TOP')
DISTRIBUTION_NAME = 'dgtset'
VALIDATOR_PKEY = '/project/peer/keys/validator.priv'
VALIDATOR_PUB_KEY = '/project/peer/keys/validator.pub'
PROJ_DGT = f'/project/{DGT_TOP}'
MAP_NET_FNM = f"{PROJ_DGT}/etc/dgt.net.map"
STATIC_MAP = "static_map"
GATE_TIPS = "gate_tips"
EMISSION_INFO = "emission"
ESIGNERS = "signers"
ESIGNER_MIN = "signer_min"

_MIN_PRINT_WIDTH = 15

def setting_key_to_address(key):
    return _key_to_address(key)

def add_config_parser(subparsers, parent_parser):
    """Creates the arg parsers needed for the config command and
    its subcommands.
    """
    parser = subparsers.add_parser(
        'config',
        help='Changes genesis block settings and create, view, and '
        'vote on settings proposals',
        description='Provides subcommands to change genesis block settings '
                    'and to view, create, and vote on existing proposals.'
    )

    config_parsers = parser.add_subparsers(title="subcommands",dest="subcommand")
    config_parsers.required = True

def get_mapping_file(fnm=MAP_NET_FNM):
    with open(fnm,"r") as map_file:                                                           
        try:                                                                                          
            map_data =  map_file.read()                                                               
            mapping = json.loads(map_data)                                                            
            return mapping                                                                               
        except Exception as ex:                                                                       
            print(f"CANT GET MAPPING FOR NET FROM={MAP_NET_FNM} ({ex})")                 
            return None                                                                               

def get_pub_key(fpub):
    try:                                                   
        with open(fpub, 'r') as key_file:                  
            pub_key_str = key_file.read().strip() 
            return pub_key_str         
    except IOError as e:                                   
        print(f"Could not load key file: {e}")             
        return None                                        


def get_net_map(fname,fpub,crypto,mapping):

    print(f"MAKE NET MAP key={fpub}...")
    pub_key_str = get_pub_key(fpub)
    if pub_key_str is None:
        return None

    try:                                                   
        with open(fname, 'r') as nest_file:                  
            nest_str = nest_file.read().strip()          
    except IOError as e:                                   
        print(f"Could not load nest file: {e}") 
        return None  

    fmap = {
             nest_str : pub_key_str,
  
           }
    gtips = {}
    emiss = { ESIGNERS : [],ESIGNER_MIN : 0}
    # add static peer into map 
    #mapping = get_mapping_file()
    esigners = []
    if mapping and STATIC_MAP in mapping:
        static_nests = {}
        for nm in mapping[STATIC_MAP]:
            clust = nm.split('.')
            nest = mapping[clust[0]][clust[1]]
            static_nests[nest] = clust
        if nest_str in static_nests:
            # add nest into first mapping
            for nest,clust in static_nests.items():
                key_file = f"{PROJ_DGT}/clusters/{clust[0]}/{clust[1]}/keys/validator.pub.{crypto}"
                pkey = get_pub_key(key_file)
                if pkey and  nest not in fmap:
                    fmap[nest] = pkey

    if mapping and GATE_TIPS in mapping:                  
        for nm,tips in mapping[GATE_TIPS].items():        
            clust = nm.split('.')                         
            nest = mapping[clust[0]][clust[1]] 
            gate = {"tips" : tips}   
            if nest in fmap:
                pkey = fmap[nest]
            else:
                # get pubkey for nest 
                key_file = f"{PROJ_DGT}/clusters/{clust[0]}/{clust[1]}/keys/validator.pub.{crypto}"  
                pkey = get_pub_key(key_file)                                                         

            # set gate addr 
            gate['addr'] = key_to_dgt_addr(pkey)
            gtips[nest] = gate                 
    if mapping and EMISSION_INFO in mapping:                                                                                 
        for snm in mapping[EMISSION_INFO][ESIGNERS]:                                                                       
            clust = snm.split('.')                                                                                        
            nest = mapping[clust[0]][clust[1]]                                                                           
            gate = {"tips" : tips}                                                                                       
            if nest in fmap:                                                                                             
                pkey = fmap[nest]                                                                                        
            else:                                                                                                        
                # get pubkey for nest                                                                                    
                key_file = f"{PROJ_DGT}/clusters/{clust[0]}/{clust[1]}/keys/validator.pub.{crypto}"                      
                pkey = get_pub_key(key_file)                                                                             
                                                                                                                         
            # set gate addr                                                                                              
            esigners.append(key_to_dgt_addr(pkey)) 
        # emission info                                                                         
        emiss[ESIGNERS] = esigners
        emiss[ESIGNER_MIN] = mapping[EMISSION_INFO][ESIGNER_MIN]



    print("MAP={} \nTIPS={}\nEMISS={}".format(fmap,gtips,emiss))
    return fmap,gtips,emiss

def get_notary_map(mapping,crypto):
    notaries = mapping[NOTARIES_MAP] 
    keys = []  
    if notaries == []:                 
        # add notary keys              
        return keys        

    for nm in notaries:  
        key_file = "{}/notaries/{}/keys/notary.pub.{}".format(PROJ_DGT,nm,crypto)                                                                
        pkey = get_pub_key(key_file)                                                            
        if pkey and  pkey not in keys:                                                          
            keys.append(pkey) 
    return keys                                                                  




def _do_config_proposal_create(args):
    """Executes the 'proposal create' subcommand.  Given a key file, and a
    series of key/value pairs, it generates batches of sawtooth_settings
    transactions in a BatchList instance.  The BatchList is either stored to a
    file or submitted to a validator, depending on the supplied CLI arguments.
    """
    signer = _read_signer(args.key,args.crypto_back)
    
    settings = [s.split('=', 1) for s in args.setting]
    #print(f"settings = {settings}")
    settings.append((args.crypto_name,args.crypto_back))
    mapping = get_mapping_file()
    first_map,gate_tips,emiss = get_net_map(args.topology_nest,args.pub_key,args.crypto_back,mapping)
    #if first_map:
    #    settings.append((args.topology_map_name,json.dumps(first_map)))

    print(f"Dgt net = {args.net_set_name}={args.net}")
    if exists(args.net):
        
        with open(args.net,"r") as file_to_load: 
            try:
                net_data =  file_to_load.read()                                
                data = json.loads(net_data)
                data[TOPO_MAP] = first_map
                data[TOPO_GATES] = gate_tips
                data[EMISSION_INFO] = emiss
                # add map into topology
                settings.append((args.net_set_name,json.dumps(data))) 
                print(f"Load Dgt net from {args.net}")
            except Exception as ex:
                print(f"Cant load {args.net} - {ex}")
                pass
    else:
        print(f"file {args.net} not exists")
    
    
    #signer = _read_signer(args.key,args.crypto_back)

    txns = [_create_propose_txn(signer, setting)
            for setting in settings]

    if NOTARIES_MAP in mapping :                                      
        notary_keys = get_notary_map(mapping,args.crypto_back)        
        if notary_keys != []:                                         
            print("NOTARY KEYS {}".format(notary_keys))  
            xtrans = create_meta_xcert_txn(signer,NOTARY_LIST_ID,{NOTARY_KEYS:notary_keys}) 
            txns.append(xtrans)            
            #settings.append((DGT_NOTARY_KEYS,','.join(notary_keys)))  

    batch = _create_batch(signer, txns)

    batch_list = BatchList(batches=[batch])

    if args.output is not None:
        try:
            with open(args.output, 'wb') as batch_file:
                batch_file.write(batch_list.SerializeToString())
        except IOError as e:
            raise CliException('Unable to write to batch file: {}'.format(str(e)))

    elif args.url is not None:
        rest_client = RestClient(args.url,token=args.access_token)
        rest_client.send_batches(batch_list)
    else:
        raise AssertionError('No target for create set.')


def _do_config_proposal_list(args):
    """Executes the 'proposal list' subcommand.

    Given a url, optional filters on prefix and public key, this command lists
    the current pending proposals for settings changes.
    """

    def _accept(candidate, public_key, prefix):
        # Check to see if the first public key matches the given public key
        # (if it is not None).  This public key belongs to the user that
        # created it.
        has_pub_key = (not public_key or candidate.votes[0].public_key == public_key)
        has_prefix = candidate.proposal.setting.startswith(prefix)
        return has_prefix and has_pub_key

    candidates_payload = _get_proposals(RestClient(args.url,token=args.access_token))
    candidates = [
        c for c in candidates_payload.candidates
        if _accept(c, args.public_key, args.filter)
    ]

    if args.format == 'default':
        for candidate in candidates:
            print('{}: {} => {}'.format(
                candidate.proposal_id,
                candidate.proposal.setting,
                candidate.proposal.value))
    elif args.format == 'csv':
        writer = csv.writer(sys.stdout, quoting=csv.QUOTE_ALL)
        writer.writerow(['PROPOSAL_ID', 'KEY', 'VALUE'])
        for candidate in candidates:
            writer.writerow([
                candidate.proposal_id,
                candidate.proposal.setting,
                candidate.proposal.value])
    elif args.format == 'json' or args.format == 'yaml':
        candidates_snapshot = \
            {c.proposal_id: {c.proposal.setting: c.proposal.value}
             for c in candidates}

        if args.format == 'json':
            print(json.dumps(candidates_snapshot, indent=2, sort_keys=True))
        else:
            print(yaml.dump(candidates_snapshot,
                            default_flow_style=False)[0:-1])
    else:
        raise AssertionError('Unknown format {}'.format(args.format))


def _do_config_proposal_vote(args):
    """Executes the 'proposal vote' subcommand.  Given a key file, a proposal
    id and a vote value, it generates a batch of dgt_settings transactions
    in a BatchList instance.  The BatchList is file or submitted to a
    validator.
    """
    signer = _read_signer(args.key,args.crypto_back)
    rest_client = RestClient(args.url,token=args.access_token)

    proposals = _get_proposals(rest_client)

    proposal = None
    for candidate in proposals.candidates:
        if candidate.proposal_id == args.proposal_id:
            proposal = candidate
            break

    if proposal is None:
        raise CliException('No proposal exists with the given id')

    for vote_record in proposal.votes:
        if vote_record.public_key == signer.get_public_key().as_hex():
            raise CliException('A vote has already been recorded with this signing key')

    txn = _create_vote_txn(
        signer,
        args.proposal_id,
        proposal.proposal.setting,
        args.vote_value)
    batch = _create_batch(signer, [txn])

    batch_list = BatchList(batches=[batch])

    rest_client.send_batches(batch_list)


def _do_config_genesis(args):
    signer = _read_signer(args.key,args.crypto_back)
    public_key = signer.get_public_key().as_hex()

    authorized_keys = args.authorized_key if args.authorized_key else [public_key]
    if args.authorized_key:
        authorized_keys = []
        for fname in args.authorized_key:
            try:                                                                  
                with open(fname, 'r') as key_file:                             
                    priv_key = key_file.read().strip()  
                    authorized_keys.append(priv_key)
            except IOError as e:                                                  
                pass
        print(f"authorized_key ={authorized_keys}")
    else:
        authorized_keys = [public_key]

    if public_key not in authorized_keys:
        authorized_keys.append(public_key)

    txns = []

    txns.append(_create_propose_txn(
        signer,
        ('sawtooth.settings.vote.authorized_keys',
         ','.join(authorized_keys))))

    if args.approval_threshold is not None:
        if args.approval_threshold < 1:
            raise CliException('approval threshold must not be less than 1')

        if args.approval_threshold > len(authorized_keys):
            raise CliException(
                'approval threshold must not be greater than the number of '
                'authorized keys')

        txns.append(_create_propose_txn(
            signer,
            ('sawtooth.settings.vote.approval_threshold',
             str(args.approval_threshold))))

    if args.notary_conf is not None:
        print(f"notary_conf ={args.notary_conf}")

    batch = _create_batch(signer, txns)
    batch_list = BatchList(batches=[batch])

    try:
        with open(args.output, 'wb') as batch_file:
            batch_file.write(batch_list.SerializeToString())
        print('Generated {}'.format(args.output))
    except IOError as e:
        raise CliException(
            'Unable to write to batch file: {}'.format(str(e)))


def _get_proposals(rest_client):
    state_leaf = rest_client.get_leaf(
        _key_to_address('sawtooth.settings.vote.proposals'))

    config_candidates = SettingCandidates()

    if state_leaf is not None:
        setting_bytes = b64decode(state_leaf['data'])
        setting = Setting()
        setting.ParseFromString(setting_bytes)

        candidates_bytes = None
        for entry in setting.entries:
            if entry.key == 'sawtooth.settings.vote.proposals':
                candidates_bytes = entry.value

        if candidates_bytes is not None:
            decoded = b64decode(candidates_bytes)
            config_candidates.ParseFromString(decoded)

    return config_candidates


def _read_signer(key_filename,crypto='bitcoin'):
    """Reads the given file as a hex key.

    Args:
        key_filename: The filename where the key is stored. If None,
            defaults to the default key for the current user.

    Returns:
        Signer: the signer

    Raises:
        CliException: If unable to read the file.
    """
    filename = key_filename
    if filename is None:
        filename = os.path.join(os.path.expanduser('~'),
                                '.dgt',
                                'keys',
                                getpass.getuser() + '.priv')

    try:
        with open(filename, 'r') as key_file:
            signing_key = key_file.read().strip()
    except IOError as e:
        raise CliException('_read_signer:Unable to read key file: {}'.format(str(e)))

    context = create_context('secp256k1',backend=crypto)
    try:
        private_key = context.from_hex(signing_key)
    except ParseError as e:
        raise CliException(f'Unable to read /{crypto}/ key in file={filename}: {e}')

    
    crypto_factory = CryptoFactory(context)
    return crypto_factory.new_signer(private_key)

def _get_topology(rest_client,args):
    """
    load topology
    """
    state_leaf = rest_client.get_leaf(_key_to_address(TOPOLOGY_SET_NM))

    #config_candidates = SettingCandidates()
    topology = None
    if state_leaf is not None:
        setting_bytes = b64decode(state_leaf['data'])
        setting = Setting()
        setting.ParseFromString(setting_bytes)
        for entry in setting.entries:
            if entry.key == TOPOLOGY_SET_NM:
                topology = json.loads(entry.value.replace("'",'"'))
                if args.cls is not None:
                    print('topology cluster',args.cls)
                    fbft = FbftTopology()
                    fbft.get_topology(topology,'','','static')
                    if args.peer is None:
                        topology = fbft.get_cluster_by_name(args.cls)
                        #print('cluster',topology)
                        """
                        for key,peer in fbft.get_cluster_iter(args.cls):
                            print('cluster',args.cls,'peer',peer)
                        """
                    else:
                        topology,_ = fbft.get_peer_by_name(args.cls,args.peer)
                    #print('CLUSTER',args.cls,args.peer,'>>>',cls)
                
        

    return topology

def _do_list_topology(args):
    """
     Executes the 'topology list' subcommand.  
    """
    #signer = _read_signer(args.key)
    rest_client = RestClient(args.url,token=args.access_token)

    topology = _get_topology(rest_client,args)

    if topology is None:
        raise CliException('No topology exists ')
    """
    for vote_record in proposal.votes:
        if vote_record.public_key == signer.get_public_key().as_hex():
            raise CliException(
                'A vote has already been recorded with this signing key')
    """
    
    print('topology ',args.cls,args.peer,'>>>',topology)
    """
    txn = _create_vote_txn(
        signer,
        args.proposal_id,
        proposal.proposal.setting,
        args.vote_value)
    batch = _create_batch(signer, [txn])

    batch_list = BatchList(batches=[batch])

    rest_client.send_batches(batch_list)
    """
def _param_show(rest_client,args):
    """
    show topology param
    """
    pref = args.param_name[:4]
    fname = ('' if pref in [ "dgt.","dgt."] else "dgt.") + args.param_name
    try:
        state_leaf = rest_client.get_leaf(_key_to_address(fname))
    except CliException:
        print('undef param {}'.format(fname))
        return

    
    if state_leaf is not None:
        setting_bytes = b64decode(state_leaf['data'])
        setting = Setting()
        setting.ParseFromString(setting_bytes)
        for entry in setting.entries:
            if entry.key == fname:
                print('{} = {}'.format(fname,entry.value))
    else:
        print('undef param {}'.format(fname))

def _param_topology(rest_client,signer,args):
    """
    set topology params
    """
    #print('_param_topology args',args,'>>>')
    if args.new == '':
        # show value
        _param_show(rest_client,args)
    else:
        #set value
        pref_nm = args.param_name[:4]
        
        fname = ('' if pref_nm in ["dgt.","dgt."]  else "dgt.") + args.param_name
        txns = [_create_propose_txn(signer, (fname,args.new))]
        batch = _create_batch(signer, txns)

        batch_list = BatchList(batches=[batch])

        if args.url is not None:
            rest_client = RestClient(args.url,token=args.access_token)
            rest_client.send_batches(batch_list)
        else:
            raise AssertionError('No target for create set.')

def _set_topology(rest_client,signer,args):
    """
    set topology
    """
    param = {}
    if args.cls:
        param['cluster'] = args.cls
    if args.peer:
        param['peer'] = args.peer
    if args.oper:
        param['oper'] = args.oper
    if args.oper:
        param['list'] = args.list
    if args.oper:
        param['pid'] = args.pid

    val = json.dumps(param, sort_keys=True, indent=4)
    print('topology val',val,'>>>')
    txns = [_create_topology_txn(signer, (TOPOLOGY_SET_NM,val))]

    batch = _create_batch(signer, txns)

    batch_list = BatchList(batches=[batch])

    if args.url is not None:
        rest_client = RestClient(args.url,token=args.access_token)
        rest_client.send_batches(batch_list)
    else:
        raise AssertionError('No target for create set.')

    

def _do_param_topology(args):
    """
     Executes the 'topology set' subcommand.  
    """
    signer = _read_signer(args.key)
    rest_client = RestClient(args.url,token=args.access_token)
    _param_topology(rest_client,signer,args)

def _do_ping_topology(args):
    """
     Executes the 'topology ping' subcommand.  
    """
    signer = _read_signer(args.key)
    rest_client = RestClient(args.url,token=args.access_token)
    args.param_name = DGT_PING_COUNTER
    args.new = "1"
    _param_topology(rest_client,signer,args)



def _do_set_topology(args):
    """
     Executes the 'topology set' subcommand.  
    """
    signer = _read_signer(args.key)
    rest_client = RestClient(args.url,token=args.access_token)

    _set_topology(rest_client,signer,args)

    print('topology SET',args.cls,args.peer,'>>>')


def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    if verbose_level == 0:
        clog.setLevel(logging.WARN)
    elif verbose_level == 1:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog


def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        help='enable more verbose output')
    """
    parent_parser.add_argument(       
        '--access_token','-atok',     
        type=str,                     
        default=None,                 
        help='Access token')          
    """

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth-DGT) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to change genesis block settings '
        'and to view, create, and vote on settings proposals.',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')
    subparsers.required = True

    # The following parser is for the `genesis` subcommand.
    # This command creates a batch that contains all of the initial
    # transactions for on-chain settings
    genesis_parser = subparsers.add_parser(
        'genesis',
        help='Creates a genesis batch file of settings transactions',
        description='Creates a Batch of settings proposals that can be '
                    'consumed by "dgtadm genesis" and used '
                    'during genesis block construction.'
    )
    genesis_parser.add_argument(
        '-k', '--key',
        type=str,
        help='specify signing key for resulting batches and initial authorized key',
        default=VALIDATOR_PKEY)

    genesis_parser.add_argument(
        '-o', '--output',
        type=str,
        default='config-genesis.batch',
        help='specify the output file for the resulting batches')

    genesis_parser.add_argument(
        '-T', '--approval-threshold',
        type=int,
        help='set the number of votes required to enable a setting change')

    genesis_parser.add_argument(
        '-A', '--authorized-key',
        type=str,
        action='append',
        help='specify a public key for the user authorized to submit '
             'config transactions')

    genesis_parser.add_argument(                
        '-nc', '--notary-conf',                       
        type=str,                            
        help='Specify a notary config file', 
        default=None #'notary.net'
        )

    genesis_parser.add_argument(                
        '-cb', '--crypto_back',              
        type=str,                            
        help='Specify a crypto back',        
        default='bitcoin')                   

    # The following parser is for the `proposal` subcommand group. These
    # commands allow the user to create proposals which may be applied
    # immediately or placed in ballot mode, depending on the current on-chain
    # settings.

    proposal_parser = subparsers.add_parser(
        'proposal',
        help='Views, creates, or votes on settings change proposals',
        description='Provides subcommands to view, create, or vote on '
                    'proposed settings')
    proposal_parsers = proposal_parser.add_subparsers(
        title='subcommands',
        dest='proposal_cmd')
    proposal_parsers.required = True

    prop_parser = proposal_parsers.add_parser(
        'create',
        help='Creates proposals for setting changes',
        parents=[base_http_parser()],
        description='Create proposals for settings changes. The change '
                    'may be applied immediately or after a series of votes, '
                    'depending on the vote threshold setting.'
    )

    prop_parser.add_argument(
        '-k', '--key',
        type=str,
        help='specify a signing key for the resulting batches',
        default=VALIDATOR_PKEY
        )
    prop_parser.add_argument(                                                 
        '-pk', '--pub_key',                                                        
        type=str,                                                             
        help='specify a publish key for this peer',               
        default=VALIDATOR_PUB_KEY                                                
        )                                                                     
    prop_parser.add_argument(                                   
        '-n', '--net',                                          
        type=str,                                               
        help='Specify a topology json file',
        default='/project/peer/etc/dgt.net') 
    prop_parser.add_argument(                      
        '-nsn', '--net_set_name',                             
        type=str,                                  
        help='Specify a topology setting',       
        default=DGT_TOPOLOGY_SET_NM)
    prop_parser.add_argument(                      
        '-cb', '--crypto_back',                             
        type=str,                                  
        help='Specify a crypto back',       
        default='bitcoin')
    prop_parser.add_argument(                 
        '-cn', '--crypto_name',               
        type=str,                             
        help='Specify a crypto setting',    
        default='dgt.crypto')  
    prop_parser.add_argument(                                     
        '-tnv', '--topology_nest',                     
        type=str,                                  
        help='Specify file with network nest for peer',              
        default=DGT_NET_NEST)                         
    prop_parser.add_argument(                      
        '-tmn', '--topology_map_name',                    
        type=str,                                  
        help='Specify a network map name',           
        default=DGT_TOPOLOGY_MAP_NM)                      





    prop_target_group = prop_parser.add_mutually_exclusive_group()
    prop_target_group.add_argument(
        '-o', '--output',
        type=str,
        help='specify the output file for the resulting batches')


    prop_parser.add_argument(
        'setting',
        type=str,
        nargs='+',
        help='configuration setting as key/value pair with the '
        'format <key>=<value>')

    proposal_list_parser = proposal_parsers.add_parser(
        'list',
        help='Lists the currently proposed (not active) settings',
        parents=[base_http_parser()],
        description='Lists the currently proposed (not active) settings. '
                    'Use this list of proposals to find proposals to '
                    'vote on.')


    proposal_list_parser.add_argument(
        '--public-key',
        type=str,
        default='',
        help='filter proposals from a particular public key')

    proposal_list_parser.add_argument(
        '--filter',
        type=str,
        default='',
        help='filter keys that begin with this value')

    proposal_list_parser.add_argument(
        '--format',
        default='default',
        choices=['default', 'csv', 'json', 'yaml'],
        help='choose the output format')

    vote_parser = proposal_parsers.add_parser(
        'vote',
        help='Votes for specific setting change proposals',
        parents=[base_http_parser()],
        description='Votes for a specific settings change proposal. Use '
                    '"dgtset proposal list" to find the proposal id.')


    vote_parser.add_argument(
        '-k', '--key',
        type=str,
        help='specify a signing key for the resulting transaction batch',
        default=VALIDATOR_PKEY
        )
    vote_parser.add_argument(           
        '-cb', '--crypto_back',            
        type=str,                          
        help='Specify a crypto back',      
        default='bitcoin')                 


    vote_parser.add_argument(
        'proposal_id',
        type=str,
        help='identify the proposal to vote on')

    vote_parser.add_argument(
        'vote_value',
        type=str,
        choices=['accept', 'reject'],
        help='specify the value of the vote')

    # add parser for topology
    #
    topology_parser = subparsers.add_parser(
        'topology',
        help='Views, creates, or change node in topology',
        description='Provides subcommands to view, create, or change '
                    'topology settings')
    topology_parsers = topology_parser.add_subparsers(
        title='subcommands',
        dest='topology_cmd')
    topology_parsers.required = True
    topology_list_parser = topology_parsers.add_parser(
        'list',
        help='Lists current topology',
        parents=[base_http_parser()],
        description='Lists the current topology  settings. '
                    )
    topology_list_parser.add_argument(
        '-c', '--cls',
        type=str,
        help='specify cluster name')
    topology_list_parser.add_argument(
        '-p', '--peer',
        type=str,
        help='specify peer name')

    
    # SET 
    topology_set_parser = topology_parsers.add_parser(
        'set',
        help='change current topology',
        parents=[base_http_parser()],
        description='change the current topology  settings. '
                    )
    topology_set_parser.add_argument(
        '-c', '--cls',
        type=str,
        help='specify cluster name')
    topology_set_parser.add_argument(
        '-p', '--peer',
        type=str,
        help='specify peer name')
    topology_set_parser.add_argument(
        '-o', '--oper',
        type=str,
        help='specify peer attribute')
    topology_set_parser.add_argument(
        '-k', '--key',
        type=str,
        help='specify signing key for resulting batches and initial authorized key',
        default=VALIDATOR_PKEY
        )
    topology_set_parser.add_argument(
        '-i', '--pid',
        type=str,
        help='specify key of peer instead of cluster+peer',
        )
    topology_set_parser.add_argument(
        '-l', '--list',
        type=str,
        help='Peers JSON description',
        )
    
    # PARAM
    topology_param_parser = topology_parsers.add_parser(
        'param',
        help='change topology settings',
        parents=[base_http_parser()],
        description='change topology  settings. '
                    )

                                                 
    topology_param_parser.add_argument(
        '-k', '--key',
        type=str,
        help='specify signing key for resulting batches and initial authorized key',
        default=VALIDATOR_PKEY
        )
    topology_param_parser.add_argument(
        'param_name',
        type=str,
        help='identify the param')

    topology_param_parser.add_argument(
        '-n', '--new',
        default='',
        type=str,
        help='identify the value of param')

    topology_ping_parser = topology_parsers.add_parser(           
        'ping',                                                   
        help='Ping DGT network', 
        parents=[base_http_parser()],                          
        description='Send ping transaction into DGT network. '                  
                    ) 

    topology_ping_parser.add_argument(                                                  
        '-k', '--key',                                                                   
        type=str,                                                                        
        help='specify signing key for resulting batches and initial authorized key',     
        default=VALIDATOR_PKEY                                   
        )                                                                                




    return parser


def main(prog_name=os.path.basename(sys.argv[0]), args=None,with_loggers=True):
    parser = create_parser(prog_name)
    if args is None:
        args = sys.argv[1:]
    args = parser.parse_args(args)

    if with_loggers is True:
        if args.verbose is None:
            verbose_level = 0
        else:
            verbose_level = args.verbose
        setup_loggers(verbose_level=verbose_level)

    if args.subcommand == 'proposal' and args.proposal_cmd == 'create':
        _do_config_proposal_create(args)
    elif args.subcommand == 'proposal' and args.proposal_cmd == 'list':
        _do_config_proposal_list(args)
    elif args.subcommand == 'proposal' and args.proposal_cmd == 'vote':
        _do_config_proposal_vote(args)
    elif args.subcommand == 'genesis':
        _do_config_genesis(args)
    elif args.subcommand == 'topology':
        if args.topology_cmd == 'list':
            _do_list_topology(args)
        elif args.topology_cmd == 'set':
            _do_set_topology(args)
        elif args.topology_cmd == 'param':
            _do_param_topology(args)
        elif args.topology_cmd == 'ping':
            _do_ping_topology(args)

        else:
            raise CliException('"{}" is not a valid subcommand of "topology"'.format(args.subcommand))
    #elif args.subcommand == 'fbft':

    else:
        raise CliException(
            '"{}" is not a valid subcommand of "config"'.format(
                args.subcommand))


def main_wrapper():
    # pylint: disable=bare-except
    try:
        main()
    except CliException as e:
        print("Error: {}".format(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        sys.stderr.close()
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
