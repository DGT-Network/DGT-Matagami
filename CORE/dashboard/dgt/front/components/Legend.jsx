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
import classNames from 'classnames/bind';
import {trimSpaces} from '../helpers/helper';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';

import humanize from '../helpers/humanize';

import Hash from './Hash';

class Legend extends React.Component {
  constructor(props){
    super(props);
    this.state = {collapsed: false};
  }

  render() {
    const {legend} = this.props;
    let t = -1;
    let tt = -1;

    return (
      <div className='card'>
        <div className='card-header' onClick={() => this.setState({collapsed: !this.state.collapsed})} data-toggle="collapse" data-target='#legend' aria-expanded="false" aria-controls="collapseExample">
          { legend == undefined || legend == null || legend.length == 0 ?
            (
              'Legend'
            ) : (
              <ul className="nav nav-tabs card-header-tabs">
              {
                legend.map((i) => {
                  t++;
                  const key = Object.keys(i)[0]
                  return (
                  <li key={`h-${key}`} className="nav-item">
                     <a className={classNames('nav-link', t == 0 ? 'active' : '' )}
                       id={`${key}-tab`}
                       data-toggle="tab"
                       href={`#${trimSpaces(key)}`}
                       role="tab">
                      {key}
                    </a>
                  </li>)
                })
              }
              </ul>
              )
          }
          <div className='close-icon text-secondary'>
            <button type="button"
                  class="btn btn-sm btn-light">
              <FontAwesomeIcon icon={this.state.collapsed ? "chevron-down" : "chevron-up"} />
            </button>
          </div>
        </div>

        <div id='legend' className="card-body collapse show">
          <div className="tab-content" id="filtercontent">
          {
            legend != null &&
            legend.map((i) => {
              tt++;
              const key = Object.keys(i)[0]
              return (
                <div key={`hg-${key}`} className={classNames("tab-pane", "fade",  tt == 0 ? 'show active' : '' )} id={trimSpaces(key)} role="tabpanel">
                  {
                    Object.keys(i[key]).map((j) => {
                      return (<div>
                        <strong>{`${j}: `}</strong>
                        <span>{humanize(i[key][j])}</span>
                        </div>)
                    })
                  }
                </div>)

            })
          }
          </div>
        </div>
     </div>
    );
  }
}

Legend.defaultProps = {
  legend: [],
}

export default Legend;
