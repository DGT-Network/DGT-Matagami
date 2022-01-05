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

import base64js from 'base64-js';
import cbor from 'borc';

export function trimHash(s, length=5) {
  if (typeof s === 'undefined') return '';
  if (s.length < 3+ 2*length)
    return s;
  else {
    let r = s.slice(0,length) + '...' + s.slice(s.length-length);
    return r;
  }
}

export function trimSpaces(s) {
  if (typeof s === 'undefined') return '';
  return s.replace(/\s/g, '');
}

export function decode(d) {
  try {
    return cbor.decode(base64js.toByteArray(d));
  }
  catch (e) {
    return {};
  }
}
