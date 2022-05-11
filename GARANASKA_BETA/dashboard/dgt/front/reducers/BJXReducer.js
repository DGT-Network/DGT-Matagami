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

import { combineReducers } from 'redux'
import {
  GET_TRANSACTIONS,
  GET_PEERS,
  SELECT_PEER,
  GET_STATE,
  GET_STATES,
  GET_BLOCKS,
  BLOCKS_LOADING,
  STATES_LOADING,
  TRANSACTIONS_LOADING,
  PEERS_LOADING,
  FILTER_PEERS,
  SHOW_MODAL
} from '../actions/actions'
import {addState} from '../logic/state'
import {filterPeers} from '../logic/peers'

const initialModalState = {
  json: {},
}

const initialState = {
  data: [],
  loading: false,
}

const initialPeersState = {
  data: [],
  selectedPeer: null,
}

function stateReducer(state=initialState, action) {
  switch(action.type) {
    case GET_STATES:
      return Object.assign({}, state, {
        data: action.data,
        loading: false,
      });

    case STATES_LOADING:
      return Object.assign({}, state, {
        loading: true,
      });

    case GET_STATE:
      return Object.assign({}, state, {
        data: addState(state.data, action.data)
      });

    default:
      return state;
  }
  return state;
}

function blocksReducer(state=initialState, action) {
  switch(action.type) {
    case GET_BLOCKS:
      return Object.assign({}, state, {
        data: action.data,
        loading: false,
      });

    case BLOCKS_LOADING:
      return Object.assign({}, state, {
        loading: true,
      });

      default:
        return state;
  }
  return state;
}

function transactionReducer(state=initialState, action) {
  switch(action.type) {
    case GET_TRANSACTIONS:
      return Object.assign({}, state, {
        data: action.data,
        loading: false,
      });

    case TRANSACTIONS_LOADING:
      return Object.assign({}, state, {
        loading: true,
      });

      default:
        return state;
  }
  return state;
}

function peersReducer(state=initialPeersState, action) {
  switch(action.type) {
    case GET_PEERS:
      return Object.assign({}, state, {
        data: action.data,
        loading: false,
      });

    case PEERS_LOADING:
      return Object.assign({}, state, {
        loading: true,
      });

      default:
        return state;
  }
  return state;
}

function modalReducer(state=initialModalState, action) {
  switch(action.type) {
    case SHOW_MODAL:
      return Object.assign({}, state, action.json);

      default:
        return state;
  }
  return state;
}

const BJXReducer = combineReducers({
  transactionReducer,
  peersReducer,
  stateReducer,
  blocksReducer,
  modalReducer,
})

export default BJXReducer;
