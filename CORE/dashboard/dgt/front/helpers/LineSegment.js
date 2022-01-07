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

class LineSegment {
  constructor(x1, y1, x2, y2) {

    this.tolerance = 1e-10;

    this.x1 = x1;
    this.y1 = y1;
    this.x2 = x2;
    this.y2 = y2;

    // Ax + By = C
    this.a = y2 - y1;
    this.b = x1 - x2;
    this.c = x1 * this.a + y1 * this.b;

    if (this.eq(this.a, 0) && this.eq(this.b, 0)) {
      throw new Error(
        'Cannot construct a LineSegment with two equal endpoints.');
    }
  }

  eq(a, b) {
    return (Math.abs(a - b) < this.tolerance);
  }

  gt(a, b) {
    return (a - b > -this.tolerance);
  }

  lt(a, b) {
    return this.gt(b, a);
  }

  offset(x, y) {
    return new LineSegment(
       this.x1 + x, this.y1 + y,
      this.x2 + x, this.y2 + y);
  }

  intersect(that) {
    var d = (this.x1 - this.x2) * (that.y1 - that.y2) -
            (this.y1 - this.y2) * (that.x1 - that.x2);

    if (this.eq(d, 0)) {
      // The two lines are parallel or very close.
      return {
        x : NaN,
        y : NaN
      };
    }

    var t1  = this.x1 * this.y2 - this.y1 * this.x2,
        t2  = that.x1 * that.y2 - that.y1 * that.x2,
        x   = (t1 * (that.x1 - that.x2) - t2 * (this.x1 - this.x2)) / d,
        y   = (t1 * (that.y1 - that.y2) - t2 * (this.y1 - this.y2)) / d,
        in1 = (this.gt(x, Math.min(this.x1, this.x2)) && this.lt(x, Math.max(this.x1, this.x2)) &&
               this.gt(y, Math.min(this.y1, this.y2)) && this.lt(y, Math.max(this.y1, this.y2))),
        in2 = (this.gt(x, Math.min(that.x1, that.x2)) && this.lt(x, Math.max(that.x1, that.x2)) &&
               this.gt(y, Math.min(that.y1, that.y2)) && this.lt(y, Math.max(that.y1, that.y2)));

    return {
      x   : x,
      y   : y,
      in1 : in1,
      in2 : in2
    };
  }
}

export default LineSegment;
