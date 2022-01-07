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

import { decode } from '../helpers/helper';

export function convertStates(data) {
  //console.log(data.data)
  data.data = data.data.map((d) => {
    d.decoded_data = decode(d.data);
    return d;
  });

  return data.data;
}

export function convertState(data, address) {

  return {
    data: data.data,
    address: address
  };

  let keys = Object.keys(data.data),
      key = null,
      decoded = null;

  if (keys.length) {
    key = keys[0];

    let p = JSON.parse(data.data[key]);

    let k = Object.keys(p)[0];
    decoded = JSON.parse(Object.values(p)[0]);
  }

  return {
    data: decoded,
    key: key,
    address: address
  };
}

export function addState(to, data) {
  return to.map((i) => {
    if (i.address === data.address)
      i.decoded_data = data;
    return i;
  });
}
