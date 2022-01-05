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

import React from 'react'
import { connect } from 'react-redux'
import classNames from 'classnames/bind'

import Hash from './Hash'

import humanize from '../helpers/humanize';

import { showModal, getTransactions } from '../actions/actions';


import ReactTable from 'react-table'
import Card from './Card'

class Transactions extends React.Component {
  constructor(props){
    super(props)

    this.state = {selectedTr: {a: 'a'}}
  }

  showDetails(info) {
    store.dispatch(showModal({
      title: 'Transaction raw details',
      json: info.original
    }))
  }

  update(){
    store.dispatch(getTransactions());
  }

  render() {
    const {transactions, columns, loading} = this.props
    return (
      <Card id='transactions_card' title='Transactions'
        btns={[{name: 'Update', handler: this.update}]}
        loading={loading}>
        {!transactions.length ? (
        <strong> No transactions</strong>
        ) : (
        <ReactTable data={transactions}
          defaultPageSize={10}
          filterable
          minRows={0}
          columns={columns}
          className='-striped'
          getTdProps={(state, rowInfo, column, instance) => {
            return {
              onClick: (e, handleOriginal) => {
                this.showDetails(rowInfo)

                // IMPORTANT! React-Table uses onClick internally to trigger
                // events like expanding SubComponents and pivots.
                // By default a custom 'onClick' handler will override this functionality.
                // If you want to fire the original onClick handler, call the
                // 'handleOriginal' function.
                if (handleOriginal) {
                  handleOriginal();
                }
              }
            };
          }}
         />
          )}
      </Card>
    )
  }
}

Transactions.defaultProps = {
  transactions: [],
  loading: false,
  columns: [
  {
    id: 'family',
    Header: 'Family name (version)',
    accessor: t => `${t.header.family_name} ${t.header.family_version}`,
  },
  {
    id: 'type',
    Header: 'Type',
    filterable: false,
    accessor: d => {
      if (d.decoded_data == undefined ||
          d.decoded_data.Verb == undefined )
        return <i>No data</i>

      return humanize(d.decoded_data.Verb)
    },
  },
  { id: 'from',
    Header: 'From',
    accessor: d => {
      if (d.decoded_data == undefined ||
          d.decoded_data.Name == undefined )
        return <i>No data</i>

      return d.decoded_data.Name
    },
  },
  { id: 'to',
    Header: 'To',
    accessor: d => {
      if (d.decoded_data == undefined ||
          d.decoded_data.to_addr == undefined )
        return <i>No data</i>

      return d.decoded_data.to_addr
    },
  },
  { id: 'amount',
    Header: 'Amount',
    filterable: false,
    accessor: d => {
      if (d.decoded_data == undefined ||
          d.decoded_data.num_bgt == undefined ||
          d.decoded_data.group_id == undefined )
        return <i>No data</i>

      return `${d.decoded_data.num_bgt} ${d.decoded_data.group_id}`
    },
  },
]
};

function mapStateToProps(store) {
  return {
    transactions: store.transactionReducer.data,
    loading: store.transactionReducer.loading,
  };
}

export default connect (mapStateToProps, null)(Transactions);
