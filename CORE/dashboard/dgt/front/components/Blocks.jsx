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
import ReactTable from "react-table";

import Hash from './Hash';
import Card from './Card';
import Graph from './Graph';

import { showModal, getBlocks } from '../actions/actions';

class Blocks extends React.Component {
  constructor(props){
    super(props);
    this.state = { selectedBlock: null};
  }

  selectBlock(ip) {
    this.setState({selectedBlock: ip});
  }

  update(){
    store.dispatch(getBlocks());
  }

  render() {
    const that = this;
    const {columns, data, loading} = this.props;
    const {selectedBlock} = this.state;

    return (
      <div>
        {
        data == null ?
        (
          <div>
            <strong> No Blocks</strong>
          </div>
        ) : (
            <div >
              <Graph data={data} id='blocks_graph' title='Ledger'
                btns={[{name: 'Update', handler: this.update}]}
                size={{width: 1000, height: 800}}
                selectedPeerIP={selectedBlock}
                onSelect={(e) => this.selectBlock(e)}
                lastN={10}
                collapseFront={false}
                loading={loading}/>

              <div className="tab-offset">
                <Card id='ledger' title='Ledger Data'
                  btns={[{name: 'Update', handler: this.update}]}
                  loading={loading}>
                  <ReactTable data={data}
                  defaultPageSize={10}
                  minRows={0}
                  columns={columns}
                  className='-striped'

                  getTdProps={(state, rowInfo, column, instance) => {
                    return {
                      onClick: (e, handleOriginal) => {
                        that.setState({
                          selectedBlock : rowInfo.row._original.header_signature,
                        })

                        store.dispatch(showModal({title: 'Block raw data',
                          json: rowInfo.row._original
                        }))

                        if (handleOriginal) {
                          handleOriginal();
                        }
                      },
                      style: {
                          background: rowInfo.row._original.header_signature === selectedBlock ? '#b8daff' :
                           rowInfo.viewIndex%2 == 0 ? 'rgba(0,0,0,.05)' : 'white',
                    },
                  }}}
                />
                </Card>
              </div>
            </div>
          )
        }
      </div>
    )
  }
}

Blocks.defaultProps = {
  data: null,
  loading: false,
  columns: [
  {
    id: 'blockNum',
    Header: 'Block Num',
    accessor: d => parseInt(d.header.block_num),
    width: 100,
  },
  { id: 'batchIds',
    Header: 'Batch ID',
    accessor: d => d.header.batch_ids.map((i) => {
          return (  <Hash key={i} hash={i}/> )
        })
  },
  { id: 'headerSignature',
    Header: 'Header Signature',
    accessor: d => <Hash hash={d.header_signature}/>,
  },
  {
    id: 'consensus',
    Header: 'Consensus',
    accessor: d => d.header.consensus,
  },
    { id: 'prevBlockId',
    Header: 'Previous Block ID',
    accessor: d => <Hash hash={d.header.previous_block_id}/>,
  },
    { id: 'signerPublicKey',
    Header: 'Signer Public Key',
    accessor: d => <Hash hash={d.header.signer_public_key}/>,
  },
    { id: 'stateRootHash',
    Header: 'State Root Hash',
    accessor: d =><Hash hash={d.header.state_root_hash}/>,
  },]
};

function mapStateToProps(store) {
  return {
    data: store.blocksReducer.data,
    loading: store.blocksReducer.loading,
  };
}

export default connect (mapStateToProps, null)(Blocks);
