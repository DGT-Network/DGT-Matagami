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
import {ForceGraph, ForceGraphNode, ForceGraphLink} from 'react-vis-force';
import axios from 'axios';
import * as d3 from "d3";
import $ from 'jquery';
import colorbrewer from 'colorbrewer';
import lodash from 'lodash'
import ReactAutocomplete from 'react-autocomplete';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import cloneDeep from 'lodash/cloneDeep';
import { connect } from 'react-redux';

import humanize from '../helpers/humanize';

import LineSegment from '../helpers/LineSegment';

import Legend from './Legend';
import Filters from './Filters';
import Card from './Card';

class Graph extends React.Component {
  constructor(props) {
    super(props);

    this.state = {collapsedNodes: [],
                  collapsedParents: [],
                  hiddenNodes: [],
                  hiddenParents: [],
                  scale: 8}

    this.selected    = {}
    this.highlighted = null
    this.collapsed = null
    this.graphh       = {}

    this.decreaseScale = this.decreaseScale.bind(this);
    this.increaseScale = this.increaseScale.bind(this);

    this.configg = {
        "title" : "",
        "graph" : {
            "linkDistance" : 60,
            "charge"       : -400,
            "height"       : 400,
            "numColors"    : 12,
            "labelPadding" : {
                "left"   : 3,
                "right"  : 3,
                "top"    : 2,
                "bottom" : 2
            },
            "labelMargin" : {
                "left"   : 3,
                "right"  : 3,
                "top"    : 2,
                "bottom" : 2
            },
            "ticksWithoutCollisions" : 50
        },
        "types" : {
            "group0" : {
                "short" : "Group 0",
                "long"  : "Group 0 long name for docs"
            },
            "group1" : {
                "short" : "Group 1",
                "long"  : "Group 1 long name for docs"
            },
            "group2" : {
                "short" : "Group 2",
                "long"  : "Group 2 long name for docs"
            },
            "group3" : {
                "short" : "Group 3",
                "long"  : "Group 3 long name for docs"
            },
            "group4" : {
                "short" : "Group 4",
                "long"  : "Group 4 long name for docs"
            },
            "group5" : {
                "short" : "Group 5",
                "long"  : "Group 5 long name for docs"
            },
            "group6" : {
                "short" : "Group 6",
                "long"  : "Group 6 long name for docs"
            },
            "group7" : {
                "short" : "Group 7",
                "long"  : "Group 7 long name for docs"
            },
            "group8" : {
                "short" : "Group 8",
                "long"  : "Group 8 long name for docs"
            },
            "group9" : {
                "short" : "Group 9",
                "long"  : "Group 9 long name for docs"
            },
            "group10" : {
                "short" : "Group 10",
                "long"  : "Group 10 long name for docs"
            }
        },
        "constraints" : [
            {
                "has"    : { "type" : "group1" },
                "type"   : "position",
                "x"      : 0.2,
                "y"      : 0.2,
                "weight" : 0.7
            }, {
                "has"    : { "type" : "group2" },
                "type"   : "position",
                "x"      : 0.8,
                "y"      : 0.2,
                "weight" : 0.7
            }, {
                "has"    : { "type" : "group3" },
                "type"   : "position",
                "x"      : 0.2,
                "y"      : 0.5,
                "weight" : 0.7
            }, {
                "has"    : { "type" : "group4" },
                "type"   : "position",
                "x"      : 0.8,
                "y"      : 0.5,
                "weight" : 0.7
            }, {
                "has"    : { "type" : "group5" },
                "type"   : "position",
                "x"      : 0.2,
                "y"      : 0.8,
                "weight" : 0.7
            }, {
                "has"    : { "type" : "group8" },
                "type"   : "position",
                "x"      : 0.8,
                "y"      : 0.8,
                "weight" : 0.7
            }
        ]
    }
  }

  increaseScale() {
    const { scale } = this.state
    if (scale == 20)
      return

    this.setState({scale: scale + 1})
    this.updateGraph();
  }

  decreaseScale() {
    const { scale } = this.state
        if (scale == 2)
      return

    this.setState({scale: scale - 1})
    this.updateGraph();

  }

  drawGraph() {
    $(`#${this.props.id}-graph`).empty();

    let that = this;

    let graph = this.graphh;
    let config = this.configg

graph.data = cloneDeep(this.props.data);

    graph.margin = {
        top    : 20,
        right  : 20,
        bottom : 20,
        left   : 20
    };

    $(`#${this.props.id}-graph`)
        .css('height', this.props.size.height + 'px')
        .css('position', 'relative');
    graph.width  = this.props.size.width  - graph.margin.left - graph.margin.right;
    graph.height = this.props.size.height - graph.margin.top  - graph.margin.bottom;

    var div = d3.select(`#${this.props.id}-graph`).append("div")
        .attr("class", "tooltip")
        .attr("id", `${this.props.id}-tooltip`)
        .style("opacity", 0)
        .style("position", "absolute");

    for (var name in graph.data) {
        var obj = graph.data[name];
        obj.positionConstraints = [];
        obj.linkStrength        = 1;

        config.constraints.forEach(function(c) {
            for (var k in c.has) {
                if (c.has[k] !== obj[k]) {
                    return true;
                }
            }

            switch (c.type) {
                case 'position':
                    obj.positionConstraints.push({
                        weight : c.weight,
                        x      : c.x * graph.width,
                        y      : c.y * graph.height
                    });
                    break;

                case 'linkStrength':
                    obj.linkStrength *= c.strength;
                    break;
            }
        });
    }

    graph.svg = d3.select(`#${this.props.id}-graph`)
      .append('svg')
        .attr('width' , this.props.size.width)//graph.width + graph.margin.right  + graph.margin.left)
        .attr('height', this.props.size.height-40)//graph.height + graph.margin.top  + graph.margin.bottom)
      .append('g')
        .attr('transform', 'translate(' + graph.margin.left + ',' + graph.margin.top + ')');

    graph.svg.classed('graph-container')
}

    wrap(text) {
      let maxLineChars = 10;
      let wrapChars = ' /_-.'.split('');
    if (text.length <= maxLineChars) {
        return [text];
    } else {
        for (var k = 0; k < wrapChars.length; k++) {
            var c = wrapChars[k];
            for (var i = maxLineChars; i >= 0; i--) {
                if (text.charAt(i) === c) {
                    var line = text.substring(0, i + 1);
                    return [line].concat(this.wrap(text.substring(i + 1)));
                }
            }
        }
        return [text.substring(0, maxLineChars)]
            .concat(this.wrap(text.substring(maxLineChars)));
    }
}

  redrawNodes() {
    let graph = this.graphh;
    let config = this.configg;

    let that = this;


    graph.svg.selectAll('*').remove();

    graph.links = [];
    for (var name in graph.data) {
        var obj = graph.data[name];
        obj.depends.forEach((depends) => {
            if (this.checkNodeHidden(obj.IP))
              return;
            var link = {
                source : graph.data.find(function r(i){return i.IP === depends}),
                target : obj
            };
            link.strength = (link.source.linkStrength || 1)
                          * (link.target.linkStrength || 1);
            graph.links.push(link);
        });
    }

    graph.categories = {};
    for (var name in graph.data) {
        var obj = graph.data[name],
            key = obj.type + ':' + (obj.group || ''),
            cat = graph.categories[key];

        obj.categoryKey = key;
        if (!cat) {
            cat = graph.categories[key] = {
                key      : key,
                type     : obj.type,
                typeName : (config.types[obj.type]
                            ? config.types[obj.type].short
                            : obj.type),
                group    : obj.group,
                count    : 0
            };
        }
        cat.count++;
    }
    graph.categoryKeys = d3.keys(graph.categories);

    graph.nodeValues = d3.values(graph.data.filter((d) => {
      return !this.checkNodeHidden(d.IP);
    }));

    graph.force = d3.layout.force()
        .nodes(graph.nodeValues)
        .links(graph.links)
        .linkStrength(function(d) { return d.strength; })
        .size([graph.width, graph.height])
        .linkDistance(this.state.scale*6)
        .charge(this.state.scale * -50)
        .on('tick', tick)


   function tick(e) {
        graph.numTicks++;

        for (var name in graph.data) {
            var obj = graph.data[name];

            obj.positionConstraints.forEach(function(c) {
                var w = c.weight * e.alpha;
                if (!isNaN(c.x)) {
                    obj.x = (c.x * w + obj.x * (1 - w));
                }
                if (!isNaN(c.y)) {
                    obj.y = (c.y * w + obj.y * (1 - w));
                }
            });
        }

        if (graph.preventCollisions) {
            //that.preventCollisions();
        }

        graph.line
            .attr('x1', function(d) {
                return d.source.x;
            })
            .attr('y1', function(d) {
                return d.source.y;
            })
            .each(function(d) {
                var x    = d.target.x,
                    y    = d.target.y,
                    line = new LineSegment(d.source.x, d.source.y, x, y);

                 for (var e in d.target.edge) {
                     var ix = line.intersect(d.target.edge[e].offset(x, y));
                    if (ix.in1 && ix.in2) {
                        x = ix.x;
                        y = ix.y;
                        break;
                    }
                 }

                d3.select(this)
                    .attr('x2', x)
                    .attr('y2', y);
            });

        graph.node
            .attr('transform', function(d) {
                return 'translate(' + d.x + ',' + d.y + ')';
});
    }



    graph.draggedThreshold = d3.scale.linear()
        .domain([0, 0.1])
        .range([5, 20])
        .clamp(true);

    function dragged(d) {
        var threshold = graph.draggedThreshold(graph.force.alpha()),
            dx        = d.oldX - d.px,
            dy        = d.oldY - d.py;
        if (Math.abs(dx) >= threshold || Math.abs(dy) >= threshold) {
            d.dragged = true;
        }
        return d.dragged;
    }

    graph.drag = d3.behavior.drag()
        .origin(function(d) { return d; })
        .on('dragstart', function(d) {
            d.oldX    = d.x;
            d.oldY    = d.y;
            d.dragged = false;
            d.fixed |= 2;
        })
        .on('drag', function(d) {
            d.px = d3.event.x;
            d.py = d3.event.y;
            if (dragged(d)) {
                if (!graph.force.alpha()) {
                    graph.force.alpha(.025);
                }
            }
        })
        .on('dragend', function(d) {
            if (!dragged(d)) {
                that.selectObject(d, this);
            }
            d.fixed &= ~6;
        });

    graph.line = graph.svg.append('g').selectAll('.link')
        .data(graph.force.links())
        .enter().append('line')
        .attr('class', 'link');

    graph.node = graph.svg.selectAll('.node')
      .data(graph.force.nodes())
      .enter().append('g')
      .attr('class', 'node')
      .call(graph.drag)
      .on('mouseover', function(d) {
            if (!that.selected.obj) {
                if (graph.mouseoutTimeout) {
                    clearTimeout(graph.mouseoutTimeout);
                    graph.mouseoutTimeout = null;
                }
                that.showTooltip(d);
                that.highlightObject(d);
            }
        })
      .on('mouseout', function() {
          if (!that.selected.obj) {
              if (graph.mouseoutTimeout) {
                  clearTimeout(graph.mouseoutTimeout);
                  graph.mouseoutTimeout = null;
              }
              graph.mouseoutTimeout = setTimeout(function() {
                  that.hideTooltip();
                  that.highlightObject(null);
              }, 100);
          }
      })
      .on('click', function(d) {
        that.selectObject(d)
      })

        //add line to graph object

      graph.nodeRect = graph.node.append('rect')
        .attr('rx', 5)
        .attr('ry', 5)
        .attr('width' , 2)
        .attr('height', 2);


      let collapse = graph.node.append('g')
        .attr('class', 'collapse-children')


      for (let i = 0; i < 3; i++){
        collapse.append('circle')
          .attr('cx', i*5)
          .attr('cy', 0)
          .attr('r' , 3)
          .attr('fill', '#666666') //'#212529'
          .attr('opacity', 0.7)

      }

      collapse.append('rect')
        .attr('x', -5)
        .attr('y', -4)
        .attr('rx', 3)
        .attr('ry', 3)
        .attr('width', 20)
        .attr('height', 8)
        .attr('opacity', 0.01)
        .attr('fill', '#FFFFFF')
        .on('click', function(d) {
          that.collapseChildren(d);
        })

      collapse = graph.node.append('g')
        .attr('class', 'collapse-parents')

      for (let i = 0; i < 3; i++){
        collapse.append('circle')
          .attr('cx', i*5)
          .attr('cy', 0)
          .attr('r' , 3)
          .attr('fill', '#666666')
          .attr('opacity', 0.7)
      }

      collapse.append('rect')
        .attr('x', -5)
        .attr('y', -4)
        .attr('rx', 3)
        .attr('ry', 3)
        .attr('width', 20)
        .attr('height', 8)
        .attr('opacity', 0.01)
        .attr('fill', '#FFFFFF')
        .on('click', function(d) {
          that.collapseParents(d);
        })

      let extradata = graph.node.append('g')
        .attr('class', 'extra-data')
        .attr('display', 'none')
        .attr('transform','translate(-35,-22)')

      extradata.append('circle')
        .attr('class', 'extra-active')
        .attr('cx', 4)
        .attr('cy', 4)
        .attr('r' , 4)
        .attr('fill', '#ffffb3')
        .attr('stroke', '#b3b37d')


        graph.node.each(function(d) {
        if (that.state.hiddenNodes.includes(d.IP))
          return;

        if (d.IP == that.props.selectedPeerIP)
            that.selectObject(d)

        var node  = d3.select(this),
            rect  = node.select('rect'),
            lines = [d.name],
            ddy   = 1.1,
            dy    = -ddy * lines.length / 2 + .5;

        lines.forEach(function(line) {
            var text = node.append('text')
                .text(function(d) {
                   return that.state.collapsedNodes.indexOf(d.IP) == -1 ? d.name : `${d.name}...`;
                })
                .attr('dy', dy + 'em');
            dy += ddy;
        });
      });

      graph.numTicks = 0;
      graph.preventCollisions = false;
      graph.force.start();

        for (var i = 0; i < 50; i++) {
            graph.force.tick();
        }
        graph.preventCollisions = true;
  }

  updateGraph(){
    let graph = this.graphh;
    let that = this;

    const container = $(`#${this.props.id}-container`)

    container.off('click').on('click', function(e) {
      if (!$(e.target).closest('.node').length) {
        that.deselectObject();
      }
    });


    graph.line.each(function(d) {
      d3.select(this).attr('display', function(d){
        return that.checkNodeHidden(d.target.IP) ||
          that.checkNodeHidden(d.source.IP) ? 'none' : 'block'
      })
    });

    graph.node.each(function(d) {
      var node   = d3.select(this),
      rect  = node.select('rect'),
      text   = node.selectAll('text'),
      collapseChildren = node.selectAll('.collapse-children'),
      collapseParents = node.selectAll('.collapse-parents'),
      extra = node.selectAll('.extra-data'),
      bounds = {}

      if (!text[0].length) return;

      text
        .each(function() {
          var box = {
            x : -23,
            y: -7,
            width: 50,
            height: 10
            }
          try {
            let box1 = this.getBBox();
            if ( box1.width != 0 || box1.height != 0){
                box = box1
            }
          }
          catch(e){
          }

          bounds.x1 = box.x;
          bounds.y1 = box.y;
          bounds.x2 = box.x + box.width;
          bounds.y2 = box.y + box.height;
        })
      .attr('text-anchor', 'middle')
      .attr('font-size', function(d) {
          return  that.checkNodeSelected(d.IP) ? that.state.scale+1 : that.state.scale
        })
      .attr('font-weight', function(d) {
          return   that.checkNodeSelected(d.IP) ? 'bold' : 'normal'
        })
      .attr('display',  function(d){
        return that.checkNodeHidden(d.IP) ? 'none' : 'block'
      })


      text.classed('inactive', d.node_state !== 'active')
        .classed('filter-disable', function(d){
          return that.checkNodeFiltered(d)
        })
        .classed('filter-enable', function(d){
          return !that.checkNodeFiltered(d)
        })


      var padding  = 5,
          margin   = 1

      //oldWidth = bounds.x2 - bounds.x1;

      //bounds.x1 -= oldWidth/2;
      //bounds.x2 -= oldWidth/2;

      bounds.x1 -= (that.checkNodeFiltered(d) ? 0 : 3) + padding;
      bounds.y1 -= (that.checkNodeFiltered(d) ? 0 : 3) + padding;
      bounds.x2 += (that.checkNodeFiltered(d) ? 0 : 3) + padding;
      bounds.y2 += (that.checkNodeFiltered(d) ? 0 : 3) + padding;

      d.extent = {
        left   : bounds.x1 - margin,
        right  : bounds.x2 + margin + margin,
        top    : bounds.y1 - margin,
        bottom : bounds.y2 + margin  + margin
      };

      d.edge = {
        left   : new LineSegment(bounds.x1, bounds.y1, bounds.x1, bounds.y2),
        right  : new LineSegment(bounds.x2, bounds.y1, bounds.x2, bounds.y2),
        top    : new LineSegment(bounds.x1, bounds.y1, bounds.x2, bounds.y1),
        bottom : new LineSegment(bounds.x1, bounds.y2, bounds.x2, bounds.y2)
      };

      rect.classed('filter-disable', function(d){
          return that.checkNodeFiltered(d)
        })
        .classed('filter-enable', function(d){
          return !that.checkNodeFiltered(d)
        })
        .attr('display',  function(d){
          return that.checkNodeHidden(d.IP) ? 'none' : 'block'
        })
        .attr('stroke', function(d) {
          return  that.colorForDarker(d)
        })
        .attr('stroke-width', function(d) {
          return   that.checkNodeSelected(d.IP) ? 3 : 1
        })
        .attr('fill', function(d) {
          return that.colorFor(d);
        })
        .attr('x', function(d) {
          return  bounds.x1 //that.checkNodeFiltered(d) ? -40 : -43
        })
        .attr('y', function(d) {
          return bounds.y1 //that.checkNodeFiltered(d) ? -13 : -16
        })
        .attr('width' , function(d) {
          return bounds.x2 - bounds.x1 //that.checkNodeFiltered(d) ? 80 : 86
        })
        .attr('height', function(d) {
          return bounds.y2 - bounds.y1 //that.checkNodeFiltered(d) ? 20 : 26
        });

      collapseChildren
        .attr('transform',`translate(${bounds.x2-10}, ${bounds.y2+6})`)
        .attr('display', function(d){
          return (!that.props.collapseFront || that.checkNodeHidden(d.IP)) ? 'none' : 'block'
        })

      collapseChildren.selectAll('circle')
        .attr('r', function(d){
          return that.checkNodeIsCollapsed(d.IP) ? 2 : 3
        })
        .attr('fill', function(d){
          return that.checkNodeIsCollapsed(d.IP) ? '#666666' : '#212529'
        })

      collapseParents
          .attr('transform',`translate(${bounds.x1 }, ${bounds.y2+6})`)
          .attr('display',  function(d){
            return (!that.props.collapseBack || that.checkNodeHidden(d.IP)) ? 'none' : 'block'
          })

      collapseParents.selectAll('circle')
        .attr('r', function(d){
          return that.checkParentIsCollapsed(d.IP) ? 2 : 3
        })
        .attr('fill', function(d){
          return that.checkParentIsCollapsed(d.IP) ? '#666666' : '#212529'
        })

      extra
        .attr('transform',`translate(${bounds.x1}, ${bounds.y1-12})`)
        .attr('display',  function(d){
          return d.node_state != undefined && !that.checkNodeHidden(d.IP) ?  'block' : 'none'
        })
        .each(function(d) {
          d3.select(this).selectAll('.extra-active')
          .attr('fill',  d.node_state != 'active' ? '#ffffb3' : '#8dd3c7' )
          .attr('stroke',  d.node_state != 'active' ? '#b3b37d' : '#63948b' )
        })
    });

    for (var i = 0; i < 50; i++) {
        graph.force.tick();
    }
  }

  checkNodeSelected(ip){
    return ip == this.props.selectedPeerIP;
  }

  checkNodeIsCollapsed(ip){
    return this.state.collapsedNodes.indexOf(ip) == -1;
  }

  checkParentIsCollapsed(ip){
    return this.state.collapsedParents.indexOf(ip) == -1;
  }


  checkNodeHidden(ip){
    return this.state.hiddenNodes.includes(ip) || this.state.hiddenParents.includes(ip);
  }

  checkNodeFiltered(d){
    const { selectedFilters, filters } = this.props;

    if (null == selectedFilters || Object.keys(selectedFilters).length == 0 )
        return true;

    const key = Object.keys(selectedFilters)[0];

    return d[key] != selectedFilters[key];
  }

  preventCollisions() {
    var quadtree = d3.geom.quadtree(graph.nodeValues);

    for (var name in graph.data) {
      var obj = graph.data[name],
          ox1 = obj.x + obj.extent.left,
          ox2 = obj.x + obj.extent.right,
          oy1 = obj.y + obj.extent.top,
          oy2 = obj.y + obj.extent.bottom;

      quadtree.visit(function(quad, x1, y1, x2, y2) {
        if (quad.point && quad.point !== obj) {
          // Check if the rectangles intersect
          var p   = quad.point,
              px1 = p.x + p.extent.left,
              px2 = p.x + p.extent.right,
              py1 = p.y + p.extent.top,
              py2 = p.y + p.extent.bottom,
              ix  = (px1 <= ox2 && ox1 <= px2 && py1 <= oy2 && oy1 <= py2);
          if (ix) {
            var xa1 = ox2 - px1, // shift obj left , p right
                xa2 = px2 - ox1, // shift obj right, p left
                ya1 = oy2 - py1, // shift obj up   , p down
                ya2 = py2 - oy1, // shift obj down , p up
                adj = Math.min(xa1, xa2, ya1, ya2);

            if (adj == xa1) {
              obj.x -= adj / 2;
              p.x   += adj / 2;
            } else if (adj == xa2) {
              obj.x += adj / 2;
              p.x   -= adj / 2;
            } else if (adj == ya1) {
              obj.y -= adj / 2;
              p.y   += adj / 2;
            } else if (adj == ya2) {
              obj.y += adj / 2;
              p.y   -= adj / 2;
            }
          }
          return ix;
        }
      });
    }
  }

  colorFor(d) {
    const { selectedFilters, filters, selectedPeerIP } = this.props;

    // if (d.IP == selectedPeerIP)
    //   return '#ffc107'

    if (null == selectedFilters || Object.keys(selectedFilters).length == 0 )
      return '#17a2b8';

    const key = Object.keys(selectedFilters)[0]

    const list = filters.filter((f) => {return f.field == key })[0].list

    return list[d[key]];
  }

  colorForDarker(d) {
    const color = this.colorFor(d)
    const percent = -0.3

    var f=parseInt(color.slice(1),16),t=percent<0?0:255,p=percent<0?percent*-1:percent,R=f>>16,G=f>>8&0x00FF,B=f&0x0000FF;
    return "#"+(0x1000000+(Math.round((t-R)*p)+R)*0x10000+(Math.round((t-G)*p)+G)*0x100+(Math.round((t-B)*p)+B)).toString(16).slice(1);
  }

  hideChildren(array, IP, except=null) {
    let graph = this.graphh;
    let el = graph.data.find((g) => {return g.IP == IP})
    el.dependedOnBy.forEach((ip) => {
      if (ip != except)
        this.hideChildren(array,ip)
    })
    if (IP != except)
      array.push(IP)
  }

  hideParents(array, IP, except = null) {
    let graph = this.graphh;
    let el = graph.data.find((g) => {return g.IP == IP})

    el.depends.forEach((ip) => {
        this.hideParents(array,ip, el.IP)
    })

    if (el.IP != except)
      el.dependedOnBy.forEach((ip) => {
        if (ip != except)
          this.hideChildren(array, ip)
      })

    if (IP != except)
      array.push(IP)
  }

  collapseChildren(obj) {
    let graph = this.graphh;

    if (this.state.collapsedNodes.indexOf(obj.IP) === -1 ){
      this.setState({collapsedNodes: this.state.collapsedNodes.concat([obj.IP]) })
    }
    else {
      this.setState({collapsedNodes: this.state.collapsedNodes.filter((ip) => {return ip != obj.IP})})
    }

    let forHide  = [];

    this.state.collapsedNodes.forEach((ip) => {
      this.hideChildren(forHide, ip, ip);
    });

    this.setState({hiddenNodes: forHide})
    this.forceUpdate();
  }

  collapseParents(obj) {
    let graph = this.graphh;

    if (this.state.collapsedParents.indexOf(obj.IP) === -1 ){
      this.setState({collapsedParents: this.state.collapsedParents.concat([obj.IP]) })
    }
    else {
      this.setState({collapsedParents: this.state.collapsedParents.filter((ip) => {return ip != obj.IP})})
    }

    let forHide  = [];

    this.state.collapsedParents.forEach((ip) => {
      this.hideParents(forHide,ip, ip)
    });


    this.setState({hiddenParents: forHide})
    this.forceUpdate();
  }

  highlightObject(obj) {
    let graph = this.graphh;
    if (obj) {
      if (obj !== this.highlighted) {
        graph.node.classed('inactive', function(d) {
          return (obj !== d
            && d.depends.indexOf(obj.name) == -1
            && d.dependedOnBy.indexOf(obj.name) == -1);
        });
        graph.line.classed('inactive', function(d) {
          return (obj !== d.source && obj !== d.target);
        });
      }
      this.highlighted = obj;
    } else {
        if (this.highlighted) {
          graph.node.classed('inactive', false);
          graph.line.classed('inactive', false);
        }
        this.highlighted = null;
    }
  }

  hideTooltip(){
    var div = d3.select(`#${this.props.id}-tooltip`)

    div.style("opacity", 0)
      .style("left", "-100px")
      .style("top", "-100px");
    }

  showTooltip(d){
    var div = d3.select(`#${this.props.id}-tooltip`)
    div.style("opacity", .9)
      .html(
          Object.keys(d.tooltip).map(key => {
              let s = isNaN(Number(key))  ?  `${key}: ` : ''
              return s + humanize(d.tooltip[key])
          }).reverse().join('<br/>'))

      .style("left", d.x - this.state.scale + "px")
      .style("top", d.y - div.node().getBoundingClientRect().height - this.state.scale + "px");
  }

  selectObject(obj) {
    this.props.onSelect(obj.IP)
  }

  deselectObject(doResize) {
    this.props.onSelect(null)
    if (this.props.onFilter != undefined)
      this.props.onFilter({})
  }

  componentDidMount() {
      this.drawGraph();
      this.redrawNodes();
  }

  componentDidUpdate(prevProps, prevState) {

    const { data, lastN, loading } = this.props;

    if (JSON.stringify(data) !== JSON.stringify(prevProps.data)) {
      this.drawGraph();
      this.redrawNodes();
      this.deselectObject();
    }

    if (data.length != prevProps.data.length &&
        lastN != null) {
      let a = [],
          b = [];
      for (let i = lastN; i < data.length; i ++){
        if (i % lastN == 0)
          a.push(data[i].IP)

      }
    this.setState({collapsedParents: a})

    let forHide  = [];
    a.forEach((ip) => {
      this.hideParents(forHide,ip, ip)
    });

    this.setState({hiddenParents: forHide})
    }

    if(!lodash.isEqual(this.state.hiddenNodes, prevState.hiddenNodes) ||
       !lodash.isEqual(this.state.hiddenParents, prevState.hiddenParents) ||
       this.state.scale != prevState.scale)
    {
      this.redrawNodes();
      this.deselectObject();
    }
    this.updateGraph();
  }

  render() {
    const {id, title, btns, loading, data, selectedPeerIP} = this.props;

    return(
      <Card id={id} title={`${title} Graph`} btns = {btns}
        loading={loading}>
        <div className='search-panel float-right'>
          <div className='input-group mb-2'>
            <div className="input-group-prepend">
              <div className="input-group-text">
                <FontAwesomeIcon icon="search" />
              </div>
            </div>

            <ReactAutocomplete
              items={data}
              shouldItemRender={(item, value) => item.IP.toLowerCase().indexOf(value.toLowerCase()) > -1}
              getItemValue={item => item.IP}
              renderItem={(item, highlighted) =>
                <div
                  key={item.IP}
                  style={{ backgroundColor: highlighted ? '#17a2b8' : 'transparent'}}>
                  {item.IP}
                </div>
              }
              value={selectedPeerIP == null ? '' : selectedPeerIP}
              onChange={e => this.props.onSelect( e.target.value)}
              onSelect={value => {this.props.onSelect(value); this.setState({ value })}}
            />
            &nbsp;
            <button type="button" class="btn btn-sm btn-light" onClick={this.decreaseScale}>-</button>
            &nbsp;
            <button type="button" class="btn btn-sm btn-light" onClick={this.increaseScale}>+</button>
          </div>
        </div>
        <div className='graphLayer'>
          <div id={`${id}-container`}>
            <div  id={`${id}-graph`}>
              <div id={`{${id}-tooltip}`} />
            </div>
          </div>
        </div>
      </Card>
    );
  }
}

Graph.defaultProps = {
  size: {
    width: 780,
    height: 350,
  },
  selectedFilters: null,
  filters: [],
  lastN: null,
  collapseBack: true,
  collapseFront: true,
  loading: false,
}

export default Graph;
