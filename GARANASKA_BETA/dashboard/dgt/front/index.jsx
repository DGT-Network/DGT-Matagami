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

import React from 'react';
import { render } from 'react-dom';

import { library } from '@fortawesome/fontawesome-svg-core';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faEnvelope,
         faChevronUp,
         faChevronDown,
         faSearch,
         faSync,
         faFilter } from '@fortawesome/free-solid-svg-icons';

import { createStore, applyMiddleware, compose } from 'redux';
import { Provider } from 'react-redux';
import thunk from 'redux-thunk';

import 'bootstrap';
import './app.scss';

import Main from './components/Main';

import BJXReducer from './reducers/BJXReducer';

import { getTransactions, getPeers, getStates, getBlocks } from './actions/actions';

library.add(faEnvelope);
library.add(faChevronUp);
library.add(faChevronDown);
library.add(faSearch);
library.add(faSync);
library.add(faFilter);


const composeEnhancer = window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__ || compose;

window.store = createStore(BJXReducer,
  composeEnhancer(applyMiddleware(thunk)),);

store.dispatch(getTransactions());
store.dispatch(getPeers());
store.dispatch(getStates());
store.dispatch(getBlocks());

render(
  <Provider store={store}>
    <Main/>
  </Provider>
  , document.getElementById("app")
);
