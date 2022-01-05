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
import { connect } from 'react-redux';
import classNames from 'classnames/bind';
import Hash from './Hash';
import DecodedData from './DecodedData';
import Card from './Card';

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';

import ReactTable from "react-table";

import { getStates, showModal } from '../actions/actions';

class State extends React.Component {
  constructor(props){
    super(props)

    this.state={search: ''}

    this.handleChange = this.handleChange.bind(this)
    this.checkSearched = this.checkSearched.bind(this)
  }

  update(){
    store.dispatch(getStates());
  }

  checkSearched(el){
    const { search } = this.state;
    if (search === '')
      return false;

    return JSON.stringify(el).includes(search);
  }

  handleChange(e) {
    this.setState({search: e.target.value})
  }


  render() {
    const {state, columns, loading} = this.props;
    return (<Card id='card_state' title='State'
      btns={[{name: 'Update', handler: this.update}]}
      loading={loading}>
      {!state.length  ? (
        <strong> No State</strong>
      ) : (
        <div>
          <div className='form-inline float-right'>
            <div className='input-group mb-2'>
                <div className="input-group-prepend">
                  <div className="input-group-text">
                    <FontAwesomeIcon icon={"filter"} />
                  </div>
                </div>
              <input type="text"
                className="form-control"
                value={this.state.search}
                onChange={this.handleChange}
                placeholder='Filter' />
            </div>
          </div>
          <div className='clearfix'>
          </div>
          <ReactTable data={state}
            defaultPageSize={10}
            columns={columns}
            minRows={0}
            className='-striped'
            getTdProps={(state, rowInfo, column, instance) => {
              return {
                onClick: (e, handleOriginal) => {
                  store.dispatch(showModal({title: 'State raw data',
                    json: rowInfo.original
                  }))

                  // IMPORTANT! React-Table uses onClick internally to trigger
                  // events like expanding SubComponents and pivots.
                  // By default a custom 'onClick' handler will override this functionality.
                  // If you want to fire the original onClick handler, call the
                  // 'handleOriginal' function.
                  if (handleOriginal) {
                    handleOriginal();
                  }
                },
                style: {
                  background: this.checkSearched(rowInfo.original) ? '#ffc107' :
                   rowInfo.viewIndex%2 == 0 ? 'rgba(0,0,0,.05)' : 'white',
                }
              };
            }}/>
        </div>
      )}
      </Card>
    );
  }
}

State.defaultProps = {
  decodedData: {},
  loading: false,
  state: [],
  columns: [{
    id: 'address',
    Header: 'Address',
    accessor: t => <Hash hash={t.address} />,
    width: 150,
  },{
    id: 'data',
    Header: 'Data',
    accessor: t => {
        return <Hash hash={t.data} /> //<DecodedData data={t.data} decodedData={t.decoded_data}/>;
    },
  }]
};

function mapStateToProps(store) {
  return {
    state: store.stateReducer.data,
    loading: store.stateReducer.loading,
  };
}

export default connect (mapStateToProps, null)(State);
