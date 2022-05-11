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
import JSONPretty from 'react-json-pretty';

import $ from 'jquery';

import { trimHash } from '../helpers/helper';

class Modal extends React.Component {
  componentDidUpdate() {
    const { json } = this.props.modal;
    if (json.length != 0)
      $('#myModal').modal('show')
  }

  render() {
    const { json, title } = this.props.modal;
    return (
      <div className="modal fade hide" id="myModal" tabIndex="-1" role="dialog" aria-labelledby="exampleModalCenterTitle" aria-hidden="true">
        <div className="modal-dialog modal-dialog-centered" role="document">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title" id="exampleModalLongTitle">{title}</h5>
              <button type="button" className="close" data-dismiss="modal" aria-label="Close">
                <span aria-hidden="true">&times;</span>
              </button>
            </div>
            <div className="modal-body">
              <JSONPretty json={json}/>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" data-dismiss="modal">Close</button>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

Modal.defaultProps = {
  modal: {
    title: '',
    json: {},
  }
}

function mapStateToProps(store) {
  return {
    modal: store.modalReducer
  };
}

export default connect (mapStateToProps, null)(Modal);
