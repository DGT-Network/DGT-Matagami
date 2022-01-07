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

import { trimHash, decode } from '../helpers/helper';

export function convertBlocks(data) {
  return data.data.map((d) => {
    const prev = data.data.find(dd => dd.header_signature == d.header.previous_block_id);

    d.name = trimHash(d.header_signature);
    d.IP = d.header_signature;
    d.tooltip = {
      1: d.header_signature,
    };
    d.depends = prev == undefined ? [] : [prev.header_signature];
    d.dependedOnBy = data.data.filter((dd) => {
        return dd.header.previous_block_id == d.header_signature;
      }).map((dd) => {return dd.header_signature});

    return d;
  })
}
