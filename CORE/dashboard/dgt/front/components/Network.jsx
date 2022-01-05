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
import {Line, Bar, Doughnut} from 'react-chartjs-2';

import Card from './Card';

import { connect } from 'react-redux';

class Network extends React.Component {

  randomInteger(min, max) {
    var rand = min + Math.random() * (max + 1 - min);
    rand = Math.floor(rand);
    return rand;
  }

  render() {
    const { nodes_count, transactions_count, transactions } = this.props;

    let success_transactions = 0;
    let failed_transactions = 0;

    if (transactions_count > 0){
      if (transactions_count < 5){
        success_transactions = 4;
        failed_transactions = 0;
      }
      else {
        success_transactions = transactions_count - 4;
        failed_transactions = 4;
      }
    }

    let generatedData = [],
    generatedLabels = [];

    for (let i = 200; i < 24*60; i+=5){
      let h = Math.floor(i / 60);
      let m = i % 60;
      generatedLabels.push(`${h}:${m}`);
      generatedData.push(this.randomInteger(200,500));
    }

    const data = {
      labels: generatedLabels,
      datasets: [
        {
          label: 'Network load',
          fill: false,
          lineTension: 0.1,
          backgroundColor: 'rgba(75,192,192,0.4)',
          borderColor: 'rgba(75,192,192,1)',
          borderCapStyle: 'butt',
          borderDash: [],
          borderDashOffset: 0.0,
          borderJoinStyle: 'miter',
          pointBorderColor: 'rgba(75,192,192,1)',
          pointBackgroundColor: '#fff',
          pointBorderWidth: 1,
          pointHoverRadius: 5,
          pointHoverBackgroundColor: 'rgba(75,192,192,1)',
          pointHoverBorderColor: 'rgba(220,220,220,1)',
          pointHoverBorderWidth: 2,
          pointRadius: 1,
          pointHitRadius: 10,
          data: generatedData
        }
      ]
    };

    const generatedData2 =[];

    transactions.forEach((t) =>
      {
        if (t.decoded_data.num_bgt === undefined || t.decoded_data.Verb != 'transfer')
          return;

        generatedData2.push(t.decoded_data.num_bgt);
      }
    )

    const generatedLabels2 = generatedData2;

    const data2 = {
      labels: generatedLabels2,
      datasets: [
        {
          label: 'Transaction',
          fill: false,
          lineTension: 0.1,
          backgroundColor: 'rgba(75,192,192,0.4)',
          borderColor: 'rgba(75,192,192,1)',
          borderCapStyle: 'butt',
          borderDash: [],
          borderDashOffset: 0.0,
          borderJoinStyle: 'miter',
          pointBorderColor: 'rgba(75,192,192,1)',
          pointBackgroundColor: '#fff',
          pointBorderWidth: 1,
          pointHoverRadius: 5,
          pointHoverBackgroundColor: 'rgba(75,192,192,1)',
          pointHoverBorderColor: 'rgba(220,220,220,1)',
          pointHoverBorderWidth: 2,
          pointRadius: 1,
          pointHitRadius: 10,
          data: generatedData2
        }
      ]
    };

    const doughData = {
      labels: [
        'Success Transactions ',
        'Failed Transactions     ',
      ],
      datasets: [{
        data: [success_transactions, failed_transactions],
        backgroundColor: [
        '#28a745',
        '#ffc107',
        ],
        hoverBackgroundColor: [
        '#28a745',
        '#ffc107',
        ]
      }]
    };

    return (<div className="tab-offset">
      <Card id="network_card" title='Network'>
          <div className='row'>
            <div className='col-8'>
              <p>
                <strong>Cluster:</strong>&nbsp;<span className='text-secondary'>eea98-0ABD7E-ff7ea-0BCDA </span>
              </p>
              <p>
                <strong>Node count:</strong>&nbsp;<span className='text-secondary'>{nodes_count}</span>
              </p>
              <p>
                <strong>Transaction count:</strong>&nbsp;
                <span className='text-secondary'>{transactions_count}&nbsp;(</span>
                <span className='text-success'>{success_transactions}</span>
                <span className='text-secondary'>/</span>
                <span className='text-warning'>{failed_transactions}</span>
                <span className='text-secondary'>)</span>
              </p>
              <p>
                <strong>DAG size:</strong>&nbsp;
                <span className='text-secondary'>{transactions_count}&nbsp;15Mb</span>
              </p>
             </div>
             <div className='col-4'>
              <Doughnut data={doughData} />
            </div>
          </div>
      </Card>

      <div className="tab-offset">
       <Card id="network_load" title='Network Load'>
          <Line data={data}
            options={{
              scales: {
                yAxes: [{
                  scaleLabel: {
                    display: true,
                    labelString: "Transaction count"
                  }
                }],
                xAxes: [{
                  scaleLabel: {
                    display: true,
                    labelString: "Time"
                  }
                }]
              }
            }}
          />
        </Card>
      </div>

       <div className="tab-offset">
        <Card id="transaction_count" title='Transaction Amount'>
          <Bar data={data2}
            options={{
              scales: {
                yAxes: [{
                  scaleLabel: {
                    display: true,
                    labelString: "BGT value"
                  }
                }],
                xAxes: [{
                  scaleLabel: {
                    display: true,
                    labelString: "Transaction"
                  }
                }]
              }
            }}
          />
        </Card>
      </div>
    </div>);
  }
}

Network.defaultProps = {
  nodes_count: 0,
  transactions_count: 0,
};


function mapStateToProps(store) {
  return {
    nodes_count: store.peersReducer.data.data == undefined ?
                  0 : store.peersReducer.data.data.length,
    transactions_count: store.transactionReducer.data == undefined ?
                  0 : store.transactionReducer.data.length,
    transactions: store.transactionReducer.data,
  };
}

export default connect (mapStateToProps, null)(Network);
