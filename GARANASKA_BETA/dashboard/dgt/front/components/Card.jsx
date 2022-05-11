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
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import classNames from 'classnames/bind';
import $ from 'jquery';

class Card extends React.Component {
  constructor(props){
    super(props);
    this.state = {collapsed: false};
    this.handleClick = this.handleClick.bind(this);
    this.collapse = this.collapse.bind(this);
  }

  collapse(){
    this.setState({collapsed: !this.state.collapsed});
    $(`#${this.props.id}`).collapse('toggle')
  }

  handleClick(e, callback){
    e.stopPropagation();
    callback();
  }


  render() {
    const {id, title, children, btns, loading} = this.props;

    return (
      <div className="card">
        <div className='card-header'
          onClick={ this.collapse }
          aria-expanded="false"
          aria-controls="collapseExample">
          {title}
          <div className='float-right close-icon text-secondary'>
            { btns.map(b =>
              (
                <button type="button"
                  class="btn btn-sm btn-light"
                  onClick={ (e) => this.handleClick(e, b.handler) }>
                {
                  b.name == 'Update' ? (
                    <FontAwesomeIcon icon={"sync"} />
                  ) : (
                    b.name
                  )
                }</button>))
            }
            <button type="button"
                  class="btn btn-sm btn-light">
              <FontAwesomeIcon icon={this.state.collapsed ? "chevron-down" : "chevron-up"} />
            </button>
          </div>
        </div>
        <div id={id} className='card-body collapse show'>
          <div className={classNames(loading ? 'd-block' : 'd-none', 'text-center text-muted')}>Loading...</div>
          <div className={classNames(loading ? 'd-none' : 'd-block')}>
            {children}
          </div>
        </div>
      </div>
    );
  }
}

Card.defaultProps = {
  btns: [],
  loading: false,
}


export default Card;
