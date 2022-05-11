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

import colorbrewer from 'colorbrewer';

export function convertPeers(data) {
  let r = [];
  convertNode(r, data.data.net_structure.parent_node );
  return {
    data: r,
    filters: convertFilters(data.data.groups, r),
  }
}

function convertFilters(filters, d){
  let f = filters.map((f) => {
    f.list = []
    d.forEach((i) => {
      if ( !f.list.includes(i[f.field]) ){
        f.list.push(i[f.field])
      }
    });
    return f;
  })

  let count =0;
  let ff = [];

  f.forEach((f) => {
    count += f.list.length;
    ff = ff.concat(f.list);
  })
  let colors = colorbrewer.Set3[count+5];

  console.log('color', colors)

  colors[1] = '#8dd3c7';
  colors[0] = '#ffffb3';

  console.log('color2', colors)

  let r = 0;

  f.forEach((f) => {
    let arr = {};
    f.list.forEach((i) => {
      return arr[i] = colors[r++];
    })
    f.list = arr;
  })

  let i={};
  ff.map((f) => { i[f] = colors[r++]; return i});

  return { filters: f, };
}

function convertNode(r, node, parent_node = null){

  let ch = [];
  let parentRelation = [];

  if (parent_node != null)
    parentRelation = [parent_node.IP];

 if (typeof node.children !== 'undefined'){
    ch = node.children;

    ch.forEach((j) => {
      convertNode(r, j, node);
    })
  }

  let legend = [];

  legend.push({"Main": {
    'Public Key': node.public_key,
    'Address': `${node.IP}:${node.port}`,
    'State': node.node_state,
    'Type': node.node_type,
    'Date Created': '15.04.2018',
    'Date Updated': '17.08.2018',
    'KYCKey': '0ABD7E',
    'SLA': 'blocked',
    'Cluster': 'eea98-0ABD7E-ff7ea-0BCDA',
    'Transactions Count' : 42,
  }})

  let keys_for_legend = Object.keys(node).filter((k) => {
  return !['IP', 'port', 'node_type', 'node_type_desc', 'node_state', 'public_key',
            'children'].includes(k) })

  keys_for_legend.forEach((k) => {
    let r = {};
    r[k] = node[k];
    legend.push( r );
    })

  r.push({
      name: node.IP,
      IP: node.IP,
      port: node.port,
      node_state: node.node_state,
      node_type: node.node_type,
      public_key:  node.public_key,
      type: node.IP,
      dependedOnBy:  ch.map((j) => {
        return j.IP;
        }),
      depends: parentRelation,
      legend: legend,
      tooltip: {
        2: node.node_type,
        1: node.node_state,
        'IP': node.IP,
      },
      filtered: false,
      raw_data: node,
    });

  return r;
}
