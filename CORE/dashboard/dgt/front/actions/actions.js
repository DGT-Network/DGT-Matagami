// Copyright 2018 NTRlab
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// -----------------------------------------------------------------------------

import axios from 'axios';

import { nodes, transactions, states, state, blocks } from '../dummies'

import { convertPeers } from '../logic/peers'
import { convertTransactions } from '../logic/transactions'
import { convertStates, convertState } from '../logic/state'
import { convertBlocks } from '../logic/blocks'

export const apiUrl = location.origin;
//const apiUrl = 'http://18.217.2.175:8003';
//const apiUrl = 'http://18.222.233.160:8003';

export const GET_TRANSACTIONS = 'GET_TRANSACTIONS';
export const GET_STATES = 'GET_STATES';
export const GET_STATE = 'GET_STATE';
export const GET_BLOCKS = 'GET_BLOCKS';
export const TRANSACTIONS_LOADING = 'TRANSACTIONS_LOADING';
export const STATES_LOADING = 'STATES_LOADING';
export const BLOCKS_LOADING = 'BLOCKS_LOADING';
export const PEERS_LOADING = 'PEERS_LOADING';
export const GET_PEERS = 'GET_PEERS';
export const SHOW_MODAL = 'SHOW_MODAL';

export function getTransactions() {
  return function(dispatch) {
    dispatch(transactionsLoading());
    return axios.get(`${apiUrl}/transactions`)
      .then( response => {
        dispatch(getTransactionsSuccess(convertTransactions(response.data)));
      })
      .catch(error => {
        console.log(error)
        // dispatch(getTransactionsSuccess(convertTransactions(transactions)));
        throw(error);
      })
  };
}

export function getStates() {
  return function(dispatch) {
    dispatch(statesLoading());
    return axios.get(`${apiUrl}/state`)
      .then( response => {
        dispatch(getStatesSuccess(convertStates(response.data)));
      })
      .catch(error => {
        throw(error);
        // dispatch(getStatesSuccess(convertStates(states)));
      })
  };
}

export function getState(address) {
  return function(dispatch) {
    return axios.get(`${apiUrl}/state/${address}`)
      .then( response => {
        dispatch(getStateSuccess(convertState(response.data, address)));
      })
      .catch(error => {
        throw(error);
      })
  };
}

export function getBlocks() {
  return function(dispatch) {
    dispatch(blocksLoading());
    return axios.get(`${apiUrl}/blocks`)
      .then( response => {
        dispatch(getBlocksSuccess(convertBlocks(response.data)));
      })
      .catch(error => {
        throw(error);
        // dispatch(getBlocksSuccess(convertBlocks(blocks)));
      })
  };
}

export function getPeers() {
  return function(dispatch) {
    dispatch(peersLoading());
    return axios.get(`${apiUrl}/peers`)
      .then( response => {
        dispatch(getPeersSuccess(convertPeers(response.data)));
      })
      .catch(error => {
        throw(error);
        // dispatch(getPeersSuccess(convertPeers(nodes)))
      })
  };
}

export function showModal(json) {
   return {
    type: SHOW_MODAL,
    json,
    };
}

function getStatesSuccess(data) {
  return {
    type: GET_STATES,
    loading: false,
    data,
    };
}

function getStateSuccess(data) {
  return {
    type: GET_STATE,
    data,
    };
}

function getBlocksSuccess(data) {
  return {
    type: GET_BLOCKS,
    loading: false,
    data,
    };
}

function getPeersSuccess(data) {
  return {
    type: GET_PEERS,
    loading: false,
    data,
    };
}

function getTransactionsSuccess(data) {
  return {
    type: GET_TRANSACTIONS,
    loading: false,
    data,
    };
}

function blocksLoading() {
  return {
    type: BLOCKS_LOADING,
    loading: true,
    };
}

function statesLoading() {
  return {
    type: STATES_LOADING,
    loading: true,
    };
}

function transactionsLoading() {
  return {
    type: TRANSACTIONS_LOADING,
    loading: true,
    };
}

function peersLoading() {
  return {
    type: PEERS_LOADING,
    loading: true,
    };
}
