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
import { apiUrl } from '../actions/actions';

import Card from './Card';

class Stat extends React.Component {
  render() {
    const data = [
      [
        ['PubKey', 'fbb1b73c4f0bda4f67dca266ce6ef42f520eea98'],
        ['KYCKey', '0ABD7E'],
        ['IP', apiUrl],
      ],
      [
        ['Name', 'BGX TEST Network'],
        ['Cluster', 'eea98-0ABD7E-ff7ea-0BCDA'],
        ['Cluster Name', 'BGX-GROUP'],
      ],
      [
        ['Parent Node', 'fbb1b73c4f0bda4f67dca266ce6ef42f520eea98'],
        ['Leader', 'fbb1b73c4f0bda4f67dca266ce6ef42f520eea98'],
        ['Genesis', 'fbb1b73c4f0bda4f67dca266ce6ef42f520eea98'],
      ],
    ];

    return (
      <div className='tab-offset'>
        <Card id="Identity" title='Identity'>
          <div className='row'>
            {
              data.map((dd) => {
                return (
                  <div key={dd[0][0]} className='col-4'>
                    {
                      dd.map((d) => {
                        return (
                          <p key={d[0]}>
                            <strong>{d[0]}:</strong>
                            <span className='text-secondary'>{` ${d[1]}`}</span>
                          </p>
                        );
                      })
                    }
                  </div>
                )
              })
            }
          </div>
        </Card>
      </div>
    );
  }
}

export default Stat;
