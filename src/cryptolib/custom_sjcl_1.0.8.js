/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

("use strict");
/*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape, module, require, Uint32Array */

/**
 * The Stanford Javascript Crypto Library, top-level namespace.
 * @namespace
 */
var sjcl = {
  /**
   * Symmetric ciphers.
   * @namespace
   */
  cipher: {},

  /**
   * Hash functions.  Right now only SHA256 is implemented.
   * @namespace
   */
  hash: {},

  /**
   * Key exchange functions.  Right now only SRP is implemented.
   * @namespace
   */
  keyexchange: {},

  /**
   * Cipher modes of operation.
   * @namespace
   */
  mode: {},

  /**
   * Miscellaneous.  HMAC and PBKDF2.
   * @namespace
   */
  misc: {},

  /**
   * Bit array encoders and decoders.
   * @namespace
   *
   * @description
   * The members of this namespace are functions which translate between
   * SJCL's bitArrays and other objects (usually strings).  Because it
   * isn't always clear which direction is encoding and which is decoding,
   * the method names are "fromBits" and "toBits".
   */
  codec: {},

  /**
   * Exceptions.
   * @namespace
   */
  exception: {
    /**
     * Ciphertext is corrupt.
     * @constructor
     */
    corrupt: function (message) {
      this.toString = function () {
        return "CORRUPT: " + this.message;
      };
      this.message = message;
    },

    /**
     * Invalid parameter.
     * @constructor
     */
    invalid: function (message) {
      this.toString = function () {
        return "INVALID: " + this.message;
      };
      this.message = message;
    },

    /**
     * Bug or missing feature in SJCL.
     * @constructor
     */
    bug: function (message) {
      this.toString = function () {
        return "BUG: " + this.message;
      };
      this.message = message;
    },

    /**
     * Something isn't ready.
     * @constructor
     */
    notReady: function (message) {
      this.toString = function () {
        return "NOT READY: " + this.message;
      };
      this.message = message;
    }
  }
};

/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Arrays of bits, encoded as arrays of Numbers.
 * @namespace
 * @description
 * <p>
 * These objects are the currency accepted by SJCL's crypto functions.
 * </p>
 *
 * <p>
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 * </p>
 *
 * <p>
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 * </p>
 */
sjcl.bitArray = {
  /**
   * Array slices in units of bits.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
   * slice until the end of the array.
   * @return {bitArray} The requested slice.
   */
  bitSlice: function (a, bstart, bend) {
    a = sjcl.bitArray
      ._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31))
      .slice(1);
    return bend === undefined ? a : sjcl.bitArray.clamp(a, bend - bstart);
  },

  /**
   * Extract a number packed into a bit array.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} blength The length of the number to extract.
   * @return {Number} The requested slice.
   */
  extract: function (a, bstart, blength) {
    // FIXME: this Math.floor is not necessary at all, but for some reason
    // seems to suppress a bug in the Chromium JIT.
    var x,
      sh = Math.floor((-bstart - blength) & 31);
    if (((bstart + blength - 1) ^ bstart) & -32) {
      // it crosses a boundary
      x =
        (a[(bstart / 32) | 0] << (32 - sh)) ^ (a[(bstart / 32 + 1) | 0] >>> sh);
    } else {
      // within a single word
      x = a[(bstart / 32) | 0] >>> sh;
    }
    return x & ((1 << blength) - 1);
  },

  /**
   * Concatenate two bit arrays.
   * @param {bitArray} a1 The first array.
   * @param {bitArray} a2 The second array.
   * @return {bitArray} The concatenation of a1 and a2.
   */
  concat: function (a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }

    var last = a1[a1.length - 1],
      shift = sjcl.bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return sjcl.bitArray._shiftRight(
        a2,
        shift,
        last | 0,
        a1.slice(0, a1.length - 1)
      );
    }
  },

  /**
   * Find the length of an array of bits.
   * @param {bitArray} a The array.
   * @return {Number} The length of a, in bits.
   */
  bitLength: function (a) {
    var l = a.length,
      x;
    if (l === 0) {
      return 0;
    }
    x = a[l - 1];
    return (l - 1) * 32 + sjcl.bitArray.getPartial(x);
  },

  /**
   * Truncate an array.
   * @param {bitArray} a The array.
   * @param {Number} len The length to truncate to, in bits.
   * @return {bitArray} A new array, truncated to len bits.
   */
  clamp: function (a, len) {
    if (a.length * 32 < len) {
      return a;
    }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l - 1] = sjcl.bitArray.partial(
        len,
        a[l - 1] & (0x80000000 >> (len - 1)),
        1
      );
    }
    return a;
  },

  /**
   * Make a partial word for a bit array.
   * @param {Number} len The number of bits in the word.
   * @param {Number} x The bits.
   * @param {Number} [_end=0] Pass 1 if x has already been shifted to the high side.
   * @return {Number} The partial word.
   */
  partial: function (len, x, _end) {
    if (len === 32) {
      return x;
    }
    return (_end ? x | 0 : x << (32 - len)) + len * 0x10000000000;
  },

  /**
   * Get the number of bits used by a partial word.
   * @param {Number} x The partial word.
   * @return {Number} The number of bits used by the partial word.
   */
  getPartial: function (x) {
    return Math.round(x / 0x10000000000) || 32;
  },

  /**
   * Compare two arrays for equality in a predictable amount of time.
   * @param {bitArray} a The first array.
   * @param {bitArray} b The second array.
   * @return {boolean} true if a == b; false otherwise.
   */
  equal: function (a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
      return false;
    }
    var x = 0,
      i;
    for (i = 0; i < a.length; i++) {
      x |= a[i] ^ b[i];
    }
    return x === 0;
  },

  /** Shift an array right.
   * @param {bitArray} a The array to shift.
   * @param {Number} shift The number of bits to shift.
   * @param {Number} [carry=0] A byte to carry in
   * @param {bitArray} [out=[]] An array to prepend to the output.
   * @private
   */
  _shiftRight: function (a, shift, carry, out) {
    var i,
      last2 = 0,
      shift2;
    if (out === undefined) {
      out = [];
    }

    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }

    for (i = 0; i < a.length; i++) {
      out.push(carry | (a[i] >>> shift));
      carry = a[i] << (32 - shift);
    }
    last2 = a.length ? a[a.length - 1] : 0;
    shift2 = sjcl.bitArray.getPartial(last2);
    out.push(
      sjcl.bitArray.partial(
        (shift + shift2) & 31,
        shift + shift2 > 32 ? carry : out.pop(),
        1
      )
    );
    return out;
  },

  /** xor a block of 4 words together.
   * @private
   */
  _xor4: function (x, y) {
    return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
  },

  /** byteswap a word array inplace.
   * (does not handle partial words)
   * @param {sjcl.bitArray} a word array
   * @return {sjcl.bitArray} byteswapped array
   */
  byteswapM: function (a) {
    var i,
      v,
      m = 0xff00;
    for (i = 0; i < a.length; ++i) {
      v = a[i];
      a[i] = (v >>> 24) | ((v >>> 8) & m) | ((v & m) << 8) | (v << 24);
    }
    return a;
  }
};
// Thanks to Colin McRae and Jonathan Burns of ionic security
// for reporting and fixing two bugs in this file!

/**
 * Constructs a new bignum from another bignum, a number or a hex string.
 * @constructor
 */
sjcl.bn = function (it) {
  this.initWith(it);
};

sjcl.bn.prototype = {
  radix: 24,
  maxMul: 8,
  _class: sjcl.bn,

  copy: function () {
    return new this._class(this);
  },

  /**
   * Initializes this with it, either as a bn, a number, or a hex string.
   */
  initWith: function (it) {
    var i = 0,
      k;
    switch (typeof it) {
      case "object":
        this.limbs = it.limbs.slice(0);
        break;

      case "number":
        this.limbs = [it];
        this.normalize();
        break;

      case "string":
        it = it.replace(/^0x/, "");
        this.limbs = [];
        // hack
        k = this.radix / 4;
        for (i = 0; i < it.length; i += k) {
          this.limbs.push(
            parseInt(
              it.substring(Math.max(it.length - i - k, 0), it.length - i),
              16
            )
          );
        }
        break;

      default:
        this.limbs = [0];
    }
    return this;
  },

  /**
   * Returns true if "this" and "that" are equal.  Calls fullReduce().
   * Equality test is in constant time.
   */
  equals: function (that) {
    if (typeof that === "number") {
      that = new this._class(that);
    }
    var difference = 0,
      i;
    this.fullReduce();
    that.fullReduce();
    for (i = 0; i < this.limbs.length || i < that.limbs.length; i++) {
      difference |= this.getLimb(i) ^ that.getLimb(i);
    }
    return difference === 0;
  },

  /**
   * Get the i'th limb of this, zero if i is too large.
   */
  getLimb: function (i) {
    return i >= this.limbs.length ? 0 : this.limbs[i];
  },

  /**
   * Constant time comparison function.
   * Returns 1 if this >= that, or zero otherwise.
   */
  greaterEquals: function (that) {
    if (typeof that === "number") {
      that = new this._class(that);
    }
    var less = 0,
      greater = 0,
      i,
      a,
      b;
    i = Math.max(this.limbs.length, that.limbs.length) - 1;
    for (; i >= 0; i--) {
      a = this.getLimb(i);
      b = that.getLimb(i);
      greater |= (b - a) & ~less;
      less |= (a - b) & ~greater;
    }
    return (greater | ~less) >>> 31;
  },

  /**
   * Convert to a hex string.
   */
  toString: function () {
    this.fullReduce();
    var out = "",
      i,
      s,
      l = this.limbs;
    for (i = 0; i < this.limbs.length; i++) {
      s = l[i].toString(16);
      while (i < this.limbs.length - 1 && s.length < 6) {
        s = "0" + s;
      }
      out = s + out;
    }
    return "0x" + out;
  },

  /** this += that.  Does not normalize. */
  addM: function (that) {
    if (typeof that !== "object") {
      that = new this._class(that);
    }
    var i,
      l = this.limbs,
      ll = that.limbs;
    for (i = l.length; i < ll.length; i++) {
      l[i] = 0;
    }
    for (i = 0; i < ll.length; i++) {
      l[i] += ll[i];
    }
    return this;
  },

  /** this *= 2.  Requires normalized; ends up normalized. */
  doubleM: function () {
    var i,
      carry = 0,
      tmp,
      r = this.radix,
      m = this.radixMask,
      l = this.limbs;
    for (i = 0; i < l.length; i++) {
      tmp = l[i];
      tmp = tmp + tmp + carry;
      l[i] = tmp & m;
      carry = tmp >> r;
    }
    if (carry) {
      l.push(carry);
    }
    return this;
  },

  /** this /= 2, rounded down.  Requires normalized; ends up normalized. */
  halveM: function () {
    var i,
      carry = 0,
      tmp,
      r = this.radix,
      l = this.limbs;
    for (i = l.length - 1; i >= 0; i--) {
      tmp = l[i];
      l[i] = (tmp + carry) >> 1;
      carry = (tmp & 1) << r;
    }
    if (!l[l.length - 1]) {
      l.pop();
    }
    return this;
  },

  /** this -= that.  Does not normalize. */
  subM: function (that) {
    if (typeof that !== "object") {
      that = new this._class(that);
    }
    var i,
      l = this.limbs,
      ll = that.limbs;
    for (i = l.length; i < ll.length; i++) {
      l[i] = 0;
    }
    for (i = 0; i < ll.length; i++) {
      l[i] -= ll[i];
    }
    return this;
  },

  mod: function (that) {
    var neg = !this.greaterEquals(new sjcl.bn(0));

    that = new sjcl.bn(that).normalize(); // copy before we begin
    var out = new sjcl.bn(this).normalize(),
      ci = 0;

    if (neg) out = new sjcl.bn(0).subM(out).normalize();

    for (; out.greaterEquals(that); ci++) {
      that.doubleM();
    }

    if (neg) out = that.sub(out).normalize();

    for (; ci > 0; ci--) {
      that.halveM();
      if (out.greaterEquals(that)) {
        out.subM(that).normalize();
      }
    }
    return out.trim();
  },

  /** return inverse mod prime p.  p must be odd. Binary extended Euclidean algorithm mod p. */
  inverseMod: function (p) {
    var a = new sjcl.bn(1),
      b = new sjcl.bn(0),
      x = new sjcl.bn(this),
      y = new sjcl.bn(p),
      tmp,
      i,
      nz = 1;

    if (!(p.limbs[0] & 1)) {
      throw new sjcl.exception.invalid("inverseMod: p must be odd");
    }

    // invariant: y is odd
    do {
      if (x.limbs[0] & 1) {
        if (!x.greaterEquals(y)) {
          // x < y; swap everything
          tmp = x;
          x = y;
          y = tmp;
          tmp = a;
          a = b;
          b = tmp;
        }
        x.subM(y);
        x.normalize();

        if (!a.greaterEquals(b)) {
          a.addM(p);
        }
        a.subM(b);
      }

      // cut everything in half
      x.halveM();
      if (a.limbs[0] & 1) {
        a.addM(p);
      }
      a.normalize();
      a.halveM();

      // check for termination: x ?= 0
      for (i = nz = 0; i < x.limbs.length; i++) {
        nz |= x.limbs[i];
      }
    } while (nz);

    if (!y.equals(1)) {
      throw new sjcl.exception.invalid(
        "inverseMod: p and x must be relatively prime"
      );
    }

    return b;
  },

  /** this + that.  Does not normalize. */
  add: function (that) {
    return this.copy().addM(that);
  },

  /** this - that.  Does not normalize. */
  sub: function (that) {
    return this.copy().subM(that);
  },

  /** this * that.  Normalizes and reduces. */
  mul: function (that) {
    if (typeof that === "number") {
      that = new this._class(that);
    } else {
      that.normalize();
    }
    this.normalize();
    var i,
      j,
      a = this.limbs,
      b = that.limbs,
      al = a.length,
      bl = b.length,
      out = new this._class(),
      c = out.limbs,
      ai,
      ii = this.maxMul;

    for (i = 0; i < this.limbs.length + that.limbs.length + 1; i++) {
      c[i] = 0;
    }
    for (i = 0; i < al; i++) {
      ai = a[i];
      for (j = 0; j < bl; j++) {
        c[i + j] += ai * b[j];
      }

      if (!--ii) {
        ii = this.maxMul;
        out.cnormalize();
      }
    }
    return out.cnormalize().reduce();
  },

  /** this ^ 2.  Normalizes and reduces. */
  square: function () {
    return this.mul(this);
  },

  /** this ^ n.  Uses square-and-multiply.  Normalizes and reduces. */
  power: function (l) {
    l = new sjcl.bn(l).normalize().trim().limbs;
    var i,
      j,
      out = new this._class(1),
      pow = this;

    for (i = 0; i < l.length; i++) {
      for (j = 0; j < this.radix; j++) {
        if (l[i] & (1 << j)) {
          out = out.mul(pow);
        }
        if (i == l.length - 1 && l[i] >> (j + 1) == 0) {
          break;
        }

        pow = pow.square();
      }
    }

    return out;
  },

  /** this * that mod N */
  mulmod: function (that, N) {
    return this.mod(N).mul(that.mod(N)).mod(N);
  },

  /** this ^ x mod N */
  powermod: function (x, N) {
    x = new sjcl.bn(x);
    N = new sjcl.bn(N);

    // Jump to montpowermod if possible.
    if ((N.limbs[0] & 1) == 1) {
      var montOut = this.montpowermod(x, N);

      if (montOut != false) {
        return montOut;
      } // else go to slow powermod
    }

    var i,
      j,
      l = x.normalize().trim().limbs,
      out = new this._class(1),
      pow = this;

    for (i = 0; i < l.length; i++) {
      for (j = 0; j < this.radix; j++) {
        if (l[i] & (1 << j)) {
          out = out.mulmod(pow, N);
        }
        if (i == l.length - 1 && l[i] >> (j + 1) == 0) {
          break;
        }

        pow = pow.mulmod(pow, N);
      }
    }

    return out;
  },

  /** this ^ x mod N with Montomery reduction */
  montpowermod: function (x, N) {
    x = new sjcl.bn(x).normalize().trim();
    N = new sjcl.bn(N);

    var i,
      j,
      radix = this.radix,
      out = new this._class(1),
      pow = this.copy();

    // Generate R as a cap of N.
    var R,
      s,
      wind,
      bitsize = x.bitLength();

    R = new sjcl.bn({
      limbs: N.copy()
        .normalize()
        .trim()
        .limbs.map(function () {
          return 0;
        })
    });

    for (s = this.radix; s > 0; s--) {
      if (((N.limbs[N.limbs.length - 1] >> s) & 1) == 1) {
        R.limbs[R.limbs.length - 1] = 1 << s;
        break;
      }
    }

    // Calculate window size as a function of the exponent's size.
    if (bitsize == 0) {
      return this;
    } else if (bitsize < 18) {
      wind = 1;
    } else if (bitsize < 48) {
      wind = 3;
    } else if (bitsize < 144) {
      wind = 4;
    } else if (bitsize < 768) {
      wind = 5;
    } else {
      wind = 6;
    }

    // Find R' and N' such that R * R' - N * N' = 1.
    var RR = R.copy(),
      NN = N.copy(),
      RP = new sjcl.bn(1),
      NP = new sjcl.bn(0),
      RT = R.copy();

    while (RT.greaterEquals(1)) {
      RT.halveM();

      if ((RP.limbs[0] & 1) == 0) {
        RP.halveM();
        NP.halveM();
      } else {
        RP.addM(NN);
        RP.halveM();

        NP.halveM();
        NP.addM(RR);
      }
    }

    RP = RP.normalize();
    NP = NP.normalize();

    RR.doubleM();
    var R2 = RR.mulmod(RR, N);

    // Check whether the invariant holds.
    // If it doesn't, we can't use Montgomery reduction on this modulus.
    if (!RR.mul(RP).sub(N.mul(NP)).equals(1)) {
      return false;
    }

    var montIn = function (c) {
        return montMul(c, R2);
      },
      montMul = function (a, b) {
        // Standard Montgomery reduction
        var k,
          ab,
          right,
          abBar,
          mask = (1 << (s + 1)) - 1;

        ab = a.mul(b);

        right = ab.mul(NP);
        right.limbs = right.limbs.slice(0, R.limbs.length);

        if (right.limbs.length == R.limbs.length) {
          right.limbs[R.limbs.length - 1] &= mask;
        }

        right = right.mul(N);

        abBar = ab.add(right).normalize().trim();
        abBar.limbs = abBar.limbs.slice(R.limbs.length - 1);

        // Division.  Equivelent to calling *.halveM() s times.
        for (k = 0; k < abBar.limbs.length; k++) {
          if (k > 0) {
            abBar.limbs[k - 1] |= (abBar.limbs[k] & mask) << (radix - s - 1);
          }

          abBar.limbs[k] = abBar.limbs[k] >> (s + 1);
        }

        if (abBar.greaterEquals(N)) {
          abBar.subM(N);
        }

        return abBar;
      },
      montOut = function (c) {
        return montMul(c, 1);
      };

    pow = montIn(pow);
    out = montIn(out);

    // Sliding-Window Exponentiation (HAC 14.85)
    var h,
      precomp = {},
      cap = (1 << (wind - 1)) - 1;

    precomp[1] = pow.copy();
    precomp[2] = montMul(pow, pow);

    for (h = 1; h <= cap; h++) {
      precomp[2 * h + 1] = montMul(precomp[2 * h - 1], precomp[2]);
    }

    var getBit = function (exp, i) {
      // Gets ith bit of exp.
      var off = i % exp.radix;

      return (exp.limbs[Math.floor(i / exp.radix)] & (1 << off)) >> off;
    };

    for (i = x.bitLength() - 1; i >= 0; ) {
      if (getBit(x, i) == 0) {
        // If the next bit is zero:
        //   Square, move forward one bit.
        out = montMul(out, out);
        i = i - 1;
      } else {
        // If the next bit is one:
        //   Find the longest sequence of bits after this one, less than `wind`
        //   bits long, that ends with a 1.  Convert the sequence into an
        //   integer and look up the pre-computed value to add.
        var l = i - wind + 1;

        while (getBit(x, l) == 0) {
          l++;
        }

        var indx = 0;
        for (j = l; j <= i; j++) {
          indx += getBit(x, j) << (j - l);
          out = montMul(out, out);
        }

        out = montMul(out, precomp[indx]);

        i = l - 1;
      }
    }

    return montOut(out);
  },

  trim: function () {
    var l = this.limbs,
      p;
    do {
      p = l.pop();
    } while (l.length && p === 0);
    l.push(p);
    return this;
  },

  /** Reduce mod a modulus.  Stubbed for subclassing. */
  reduce: function () {
    return this;
  },

  /** Reduce and normalize. */
  fullReduce: function () {
    return this.normalize();
  },

  /** Propagate carries. */
  normalize: function () {
    var carry = 0,
      i,
      pv = this.placeVal,
      ipv = this.ipv,
      l,
      m,
      limbs = this.limbs,
      ll = limbs.length,
      mask = this.radixMask;
    for (i = 0; i < ll || (carry !== 0 && carry !== -1); i++) {
      l = (limbs[i] || 0) + carry;
      m = limbs[i] = l & mask;
      carry = (l - m) * ipv;
    }
    if (carry === -1) {
      limbs[i - 1] -= pv;
    }
    this.trim();
    return this;
  },

  /** Constant-time normalize. Does not allocate additional space. */
  cnormalize: function () {
    var carry = 0,
      i,
      ipv = this.ipv,
      l,
      m,
      limbs = this.limbs,
      ll = limbs.length,
      mask = this.radixMask;
    for (i = 0; i < ll - 1; i++) {
      l = limbs[i] + carry;
      m = limbs[i] = l & mask;
      carry = (l - m) * ipv;
    }
    limbs[i] += carry;
    return this;
  },

  /** Serialize to a bit array */
  toBits: function (len) {
    this.fullReduce();
    len = len || this.exponent || this.bitLength();
    var i = Math.floor((len - 1) / 24),
      w = sjcl.bitArray,
      e = ((len + 7) & -8) % this.radix || this.radix,
      out = [w.partial(e, this.getLimb(i))];
    for (i--; i >= 0; i--) {
      out = w.concat(out, [
        w.partial(Math.min(this.radix, len), this.getLimb(i))
      ]);
      len -= this.radix;
    }
    return out;
  },

  /** Return the length in bits, rounded up to the nearest byte. */
  bitLength: function () {
    this.fullReduce();
    var out = this.radix * (this.limbs.length - 1),
      b = this.limbs[this.limbs.length - 1];
    for (; b; b >>>= 1) {
      out++;
    }
    return (out + 7) & -8;
  }
};

/** @memberOf sjcl.bn
 * @this { sjcl.bn }
 */
sjcl.bn.fromBits = function (bits) {
  var Class = this,
    out = new Class(),
    words = [],
    w = sjcl.bitArray,
    t = this.prototype,
    l = Math.min(this.bitLength || 0x100000000, w.bitLength(bits)),
    e = l % t.radix || t.radix;

  words[0] = w.extract(bits, 0, e);
  for (; e < l; e += t.radix) {
    words.unshift(w.extract(bits, e, t.radix));
  }

  out.limbs = words;
  return out;
};

sjcl.bn.prototype.ipv =
  1 / (sjcl.bn.prototype.placeVal = Math.pow(2, sjcl.bn.prototype.radix));
sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1;

/**
 * Creates a new subclass of bn, based on reduction modulo a pseudo-Mersenne prime,
 * i.e. a prime of the form 2^e + sum(a * 2^b),where the sum is negative and sparse.
 */
sjcl.bn.pseudoMersennePrime = function (exponent, coeff) {
  /** @constructor
   * @private
   */
  function p(it) {
    this.initWith(it);
    /*if (this.limbs[this.modOffset]) {
      this.reduce();
    }*/
  }

  var ppr = (p.prototype = new sjcl.bn()),
    i,
    tmp,
    mo;
  mo = ppr.modOffset = Math.ceil((tmp = exponent / ppr.radix));
  ppr.exponent = exponent;
  ppr.offset = [];
  ppr.factor = [];
  ppr.minOffset = mo;
  ppr.fullMask = 0;
  ppr.fullOffset = [];
  ppr.fullFactor = [];
  ppr.modulus = p.modulus = new sjcl.bn(Math.pow(2, exponent));

  ppr.fullMask = 0 | -Math.pow(2, exponent % ppr.radix);

  for (i = 0; i < coeff.length; i++) {
    ppr.offset[i] = Math.floor(coeff[i][0] / ppr.radix - tmp);
    ppr.fullOffset[i] = Math.floor(coeff[i][0] / ppr.radix) - mo + 1;
    ppr.factor[i] =
      coeff[i][1] *
      Math.pow(1 / 2, exponent - coeff[i][0] + ppr.offset[i] * ppr.radix);
    ppr.fullFactor[i] =
      coeff[i][1] *
      Math.pow(1 / 2, exponent - coeff[i][0] + ppr.fullOffset[i] * ppr.radix);
    ppr.modulus.addM(new sjcl.bn(Math.pow(2, coeff[i][0]) * coeff[i][1]));
    ppr.minOffset = Math.min(ppr.minOffset, -ppr.offset[i]); // conservative
  }
  ppr._class = p;
  ppr.modulus.cnormalize();

  /** Approximate reduction mod p.  May leave a number which is negative or slightly larger than p.
   * @memberof sjcl.bn
   * @this { sjcl.bn }
   */
  ppr.reduce = function () {
    var i,
      k,
      l,
      mo = this.modOffset,
      limbs = this.limbs,
      off = this.offset,
      ol = this.offset.length,
      fac = this.factor,
      ll;

    i = this.minOffset;
    while (limbs.length > mo) {
      l = limbs.pop();
      ll = limbs.length;
      for (k = 0; k < ol; k++) {
        limbs[ll + off[k]] -= fac[k] * l;
      }

      i--;
      if (!i) {
        limbs.push(0);
        this.cnormalize();
        i = this.minOffset;
      }
    }
    this.cnormalize();

    return this;
  };

  /** @memberof sjcl.bn
   * @this { sjcl.bn }
   */
  ppr._strongReduce =
    ppr.fullMask === -1
      ? ppr.reduce
      : function () {
          var limbs = this.limbs,
            i = limbs.length - 1,
            k,
            l;
          this.reduce();
          if (i === this.modOffset - 1) {
            l = limbs[i] & this.fullMask;
            limbs[i] -= l;
            for (k = 0; k < this.fullOffset.length; k++) {
              limbs[i + this.fullOffset[k]] -= this.fullFactor[k] * l;
            }
            this.normalize();
          }
        };

  /** mostly constant-time, very expensive full reduction.
   * @memberof sjcl.bn
   * @this { sjcl.bn }
   */
  ppr.fullReduce = function () {
    var greater, i;
    // massively above the modulus, may be negative

    this._strongReduce();
    // less than twice the modulus, may be negative

    this.addM(this.modulus);
    this.addM(this.modulus);
    this.normalize();
    // probably 2-3x the modulus

    this._strongReduce();
    // less than the power of 2.  still may be more than
    // the modulus

    // HACK: pad out to this length
    for (i = this.limbs.length; i < this.modOffset; i++) {
      this.limbs[i] = 0;
    }

    // constant-time subtract modulus
    greater = this.greaterEquals(this.modulus);
    for (i = 0; i < this.limbs.length; i++) {
      this.limbs[i] -= this.modulus.limbs[i] * greater;
    }
    this.cnormalize();

    return this;
  };

  /** @memberof sjcl.bn
   * @this { sjcl.bn }
   */
  ppr.inverse = function () {
    return this.power(this.modulus.sub(2));
  };

  p.fromBits = sjcl.bn.fromBits;

  return p;
};

// a small Mersenne prime
var sbp = sjcl.bn.pseudoMersennePrime;
sjcl.bn.prime = {
  p127: sbp(127, [[0, -1]]),

  // Bernstein's prime for Curve25519
  p25519: sbp(255, [[0, -19]]),

  // Koblitz primes
  p192k: sbp(192, [
    [32, -1],
    [12, -1],
    [8, -1],
    [7, -1],
    [6, -1],
    [3, -1],
    [0, -1]
  ]),
  p224k: sbp(224, [
    [32, -1],
    [12, -1],
    [11, -1],
    [9, -1],
    [7, -1],
    [4, -1],
    [1, -1],
    [0, -1]
  ]),
  p256k: sbp(256, [
    [32, -1],
    [9, -1],
    [8, -1],
    [7, -1],
    [6, -1],
    [4, -1],
    [0, -1]
  ]),

  // NIST primes
  p192: sbp(192, [
    [0, -1],
    [64, -1]
  ]),
  p224: sbp(224, [
    [0, 1],
    [96, -1]
  ]),
  p256: sbp(256, [
    [0, -1],
    [96, 1],
    [192, 1],
    [224, -1]
  ]),
  p384: sbp(384, [
    [0, -1],
    [32, 1],
    [96, -1],
    [128, -1]
  ]),
  p521: sbp(521, [[0, -1]])
};

sjcl.bn.random = function (modulus, paranoia) {
  if (typeof modulus !== "object") {
    modulus = new sjcl.bn(modulus);
  }
  var words,
    i,
    l = modulus.limbs.length,
    m = modulus.limbs[l - 1] + 1,
    out = new sjcl.bn();
  while (true) {
    // get a sequence whose first digits make sense
    do {
      words = sjcl.random.randomWords(l, paranoia);
      if (words[l - 1] < 0) {
        words[l - 1] += 0x100000000;
      }
    } while (Math.floor(words[l - 1] / m) === Math.floor(0x100000000 / m));
    words[l - 1] %= m;

    // mask off all the limbs
    for (i = 0; i < l - 1; i++) {
      words[i] &= modulus.radixMask;
    }

    // check the rest of the digitssj
    out.limbs = words;
    if (!out.greaterEquals(modulus)) {
      return out;
    }
  }
};
/** @fileOverview Really fast & small implementation of CCM using JS' array buffers
 *
 * @author Marco Munizaga
 */

/**
 * CTR mode with CBC MAC.
 * @namespace
 */
sjcl.arrayBuffer = sjcl.arrayBuffer || {};

//patch arraybuffers if they don't exist
if (typeof ArrayBuffer === "undefined") {
  (function (globals) {
    "use strict";
    globals.ArrayBuffer = function () {};
    globals.DataView = function () {};
  })(this);
}

sjcl.arrayBuffer.ccm = {
  mode: "ccm",

  defaults: {
    tlen: 128 //this is M in the NIST paper
  },

  /** Encrypt in CCM mode. Meant to return the same exact thing as the bitArray ccm to work as a drop in replacement
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=64] the desired tag length, in bits.
   * @return {bitArray} The encrypted data, an array of bytes.
   */
  compat_encrypt: function (prf, plaintext, iv, adata, tlen) {
    var plaintext_buffer = sjcl.codec.arrayBuffer.fromBits(plaintext, true, 16),
      ol = sjcl.bitArray.bitLength(plaintext) / 8,
      encrypted_obj,
      ct,
      tag;

    tlen = tlen || 64;
    adata = adata || [];

    encrypted_obj = sjcl.arrayBuffer.ccm.encrypt(
      prf,
      plaintext_buffer,
      iv,
      adata,
      tlen,
      ol
    );
    ct = sjcl.codec.arrayBuffer.toBits(encrypted_obj.ciphertext_buffer);

    ct = sjcl.bitArray.clamp(ct, ol * 8);

    return sjcl.bitArray.concat(ct, encrypted_obj.tag);
  },

  /** Decrypt in CCM mode. Meant to imitate the bitArray ccm
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] adata The authenticated data.
   * @param {Number} [tlen=64] tlen the desired tag length, in bits.
   * @return {bitArray} The decrypted data.
   */
  compat_decrypt: function (prf, ciphertext, iv, adata, tlen) {
    tlen = tlen || 64;
    adata = adata || [];
    var L,
      i,
      w = sjcl.bitArray,
      ol = w.bitLength(ciphertext),
      out = w.clamp(ciphertext, ol - tlen),
      tag = w.bitSlice(ciphertext, ol - tlen),
      tag2,
      ciphertext_buffer = sjcl.codec.arrayBuffer.fromBits(out, true, 16);

    var plaintext_buffer = sjcl.arrayBuffer.ccm.decrypt(
      prf,
      ciphertext_buffer,
      iv,
      tag,
      adata,
      tlen,
      (ol - tlen) / 8
    );
    return sjcl.bitArray.clamp(
      sjcl.codec.arrayBuffer.toBits(plaintext_buffer),
      ol - tlen
    );
  },

  /** Really fast ccm encryption, uses arraybufer and mutates the plaintext buffer
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {ArrayBuffer} plaintext_buffer The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {ArrayBuffer} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] the desired tag length, in bits.
   * @return {ArrayBuffer} The encrypted data, in the same array buffer as the given plaintext, but given back anyways
   */
  encrypt: function (prf, plaintext_buffer, iv, adata, tlen, ol) {
    var auth_blocks,
      mac,
      L,
      w = sjcl.bitArray,
      ivl = w.bitLength(iv) / 8;

    //set up defaults
    adata = adata || [];
    tlen = tlen || sjcl.arrayBuffer.ccm.defaults.tlen;
    ol = ol || plaintext_buffer.byteLength;
    tlen = Math.ceil(tlen / 8);

    for (L = 2; L < 4 && ol >>> (8 * L); L++) {}
    if (L < 15 - ivl) {
      L = 15 - ivl;
    }
    iv = w.clamp(iv, 8 * (15 - L));

    //prf should use a 256 bit key to make precomputation attacks infeasible

    mac = sjcl.arrayBuffer.ccm._computeTag(
      prf,
      plaintext_buffer,
      iv,
      adata,
      tlen,
      ol,
      L
    );

    //encrypt the plaintext and the mac
    //returns the mac since the plaintext will be left encrypted inside the buffer
    mac = sjcl.arrayBuffer.ccm._ctrMode(
      prf,
      plaintext_buffer,
      iv,
      mac,
      tlen,
      L
    );

    //the plaintext_buffer has been modified so it is now the ciphertext_buffer
    return { ciphertext_buffer: plaintext_buffer, tag: mac };
  },

  /** Really fast ccm decryption, uses arraybufer and mutates the given buffer
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {ArrayBuffer} ciphertext_buffer The Ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} The authentication tag for the ciphertext
   * @param {ArrayBuffer} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] the desired tag length, in bits.
   * @return {ArrayBuffer} The decrypted data, in the same array buffer as the given buffer, but given back anyways
   */
  decrypt: function (prf, ciphertext_buffer, iv, tag, adata, tlen, ol) {
    var mac,
      mac2,
      i,
      L,
      w = sjcl.bitArray,
      ivl = w.bitLength(iv) / 8;

    //set up defaults
    adata = adata || [];
    tlen = tlen || sjcl.arrayBuffer.ccm.defaults.tlen;
    ol = ol || ciphertext_buffer.byteLength;
    tlen = Math.ceil(tlen / 8);

    for (L = 2; L < 4 && ol >>> (8 * L); L++) {}
    if (L < 15 - ivl) {
      L = 15 - ivl;
    }
    iv = w.clamp(iv, 8 * (15 - L));

    //prf should use a 256 bit key to make precomputation attacks infeasible

    //decrypt the buffer
    mac = sjcl.arrayBuffer.ccm._ctrMode(
      prf,
      ciphertext_buffer,
      iv,
      tag,
      tlen,
      L
    );

    mac2 = sjcl.arrayBuffer.ccm._computeTag(
      prf,
      ciphertext_buffer,
      iv,
      adata,
      tlen,
      ol,
      L
    );

    //check the tag
    if (!sjcl.bitArray.equal(mac, mac2)) {
      throw new sjcl.exception.corrupt("ccm: tag doesn't match");
    }

    return ciphertext_buffer;
  },

  /* Compute the (unencrypted) authentication tag, according to the CCM specification
   * @param {Object} prf The pseudorandom function.
   * @param {ArrayBuffer} data_buffer The plaintext data in an arraybuffer.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} adata The authenticated data.
   * @param {Number} tlen the desired tag length, in bits.
   * @return {bitArray} The tag, but not yet encrypted.
   * @private
   */
  _computeTag: function (prf, data_buffer, iv, adata, tlen, ol, L) {
    var i,
      plaintext,
      mac,
      data,
      data_blocks_size,
      data_blocks,
      w = sjcl.bitArray,
      tmp,
      macData;

    mac = sjcl.mode.ccm._macAdditionalData(prf, adata, iv, tlen, ol, L);

    if (data_buffer.byteLength !== 0) {
      data = new DataView(data_buffer);
      //set padding bytes to 0
      for (i = ol; i < data_buffer.byteLength; i++) {
        data.setUint8(i, 0);
      }

      //now to mac the plaintext blocks
      for (i = 0; i < data.byteLength; i += 16) {
        mac[0] ^= data.getUint32(i);
        mac[1] ^= data.getUint32(i + 4);
        mac[2] ^= data.getUint32(i + 8);
        mac[3] ^= data.getUint32(i + 12);

        mac = prf.encrypt(mac);
      }
    }

    return sjcl.bitArray.clamp(mac, tlen * 8);
  },

  /** CCM CTR mode.
   * Encrypt or decrypt data and tag with the prf in CCM-style CTR mode.
   * Mutates given array buffer
   * @param {Object} prf The PRF.
   * @param {ArrayBuffer} data_buffer The data to be encrypted or decrypted.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} tag The authentication tag.
   * @param {Number} tlen The length of th etag, in bits.
   * @return {Object} An object with data and tag, the en/decryption of data and tag values.
   * @private
   */
  _ctrMode: function (prf, data_buffer, iv, mac, tlen, L) {
    var data,
      ctr,
      word0,
      word1,
      word2,
      word3,
      keyblock,
      i,
      w = sjcl.bitArray,
      xor = w._xor4,
      n = data_buffer.byteLength / 50,
      p = n;

    ctr = new DataView(new ArrayBuffer(16)); //create the first block for the counter

    //prf should use a 256 bit key to make precomputation attacks infeasible

    // start the ctr
    ctr = w
      .concat([w.partial(8, L - 1)], iv)
      .concat([0, 0, 0])
      .slice(0, 4);

    // en/decrypt the tag
    mac = w.bitSlice(xor(mac, prf.encrypt(ctr)), 0, tlen * 8);

    ctr[3]++;
    if (ctr[3] === 0) ctr[2]++; //increment higher bytes if the lowest 4 bytes are 0

    if (data_buffer.byteLength !== 0) {
      data = new DataView(data_buffer);
      //now lets encrypt the message
      for (i = 0; i < data.byteLength; i += 16) {
        if (i > n) {
          sjcl.mode.ccm._callProgressListener(i / data_buffer.byteLength);
          n += p;
        }
        keyblock = prf.encrypt(ctr);

        word0 = data.getUint32(i);
        word1 = data.getUint32(i + 4);
        word2 = data.getUint32(i + 8);
        word3 = data.getUint32(i + 12);

        data.setUint32(i, word0 ^ keyblock[0]);
        data.setUint32(i + 4, word1 ^ keyblock[1]);
        data.setUint32(i + 8, word2 ^ keyblock[2]);
        data.setUint32(i + 12, word3 ^ keyblock[3]);

        ctr[3]++;
        if (ctr[3] === 0) ctr[2]++; //increment higher bytes if the lowest 4 bytes are 0
      }
    }

    //return the mac, the ciphered data is available through the same data_buffer that was given
    return mac;
  }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Marco Munizaga
 */

//patch arraybuffers if they don't exist
if (typeof ArrayBuffer === "undefined") {
  (function (globals) {
    "use strict";
    globals.ArrayBuffer = function () {};
    globals.DataView = function () {};
  })(this);
}

/**
 * ArrayBuffer
 * @namespace
 */
sjcl.codec.arrayBuffer = {
  /** Convert from a bitArray to an ArrayBuffer.
   * Will default to 8byte padding if padding is undefined*/
  fromBits: function (arr, padding, padding_count) {
    var out, i, ol, tmp, smallest;
    padding = padding == undefined ? true : padding;
    padding_count = padding_count || 8;

    if (arr.length === 0) {
      return new ArrayBuffer(0);
    }

    ol = sjcl.bitArray.bitLength(arr) / 8;

    //check to make sure the bitLength is divisible by 8, if it isn't
    //we can't do anything since arraybuffers work with bytes, not bits
    if (sjcl.bitArray.bitLength(arr) % 8 !== 0) {
      throw new sjcl.exception.invalid(
        "Invalid bit size, must be divisble by 8 to fit in an arraybuffer correctly"
      );
    }

    if (padding && ol % padding_count !== 0) {
      ol += padding_count - (ol % padding_count);
    }

    //padded temp for easy copying
    tmp = new DataView(new ArrayBuffer(arr.length * 4));
    for (i = 0; i < arr.length; i++) {
      tmp.setUint32(i * 4, arr[i] << 32); //get rid of the higher bits
    }

    //now copy the final message if we are not going to 0 pad
    out = new DataView(new ArrayBuffer(ol));

    //save a step when the tmp and out bytelength are ===
    if (out.byteLength === tmp.byteLength) {
      return tmp.buffer;
    }

    smallest =
      tmp.byteLength < out.byteLength ? tmp.byteLength : out.byteLength;
    for (i = 0; i < smallest; i++) {
      out.setUint8(i, tmp.getUint8(i));
    }

    return out.buffer;
  },
  /** Convert from an ArrayBuffer to a bitArray. */
  toBits: function (buffer) {
    var i,
      out = [],
      len,
      inView,
      tmp;

    if (buffer.byteLength === 0) {
      return [];
    }

    inView = new DataView(buffer);
    len = inView.byteLength - (inView.byteLength % 4);

    for (var i = 0; i < len; i += 4) {
      out.push(inView.getUint32(i));
    }

    if (inView.byteLength % 4 != 0) {
      tmp = new DataView(new ArrayBuffer(4));
      for (var i = 0, l = inView.byteLength % 4; i < l; i++) {
        //we want the data to the right, because partial slices off the starting bits
        tmp.setUint8(i + 4 - l, inView.getUint8(len + i)); // big-endian,
      }
      out.push(
        sjcl.bitArray.partial((inView.byteLength % 4) * 8, tmp.getUint32(0))
      );
    }
    return out;
  },

  /** Prints a hex output of the buffer contents, akin to hexdump **/
  hexDumpBuffer: function (buffer) {
    var stringBufferView = new DataView(buffer);
    var string = "";
    var pad = function (n, width) {
      n = n + "";
      return n.length >= width
        ? n
        : new Array(width - n.length + 1).join("0") + n;
    };

    for (var i = 0; i < stringBufferView.byteLength; i += 2) {
      if (i % 16 == 0) string += "\n" + i.toString(16) + "\t";
      string += pad(stringBufferView.getUint16(i).toString(16), 4) + " ";
    }

    if (typeof console === undefined) {
      console = console || { log: function () {} }; //fix for IE
    }
    console.log(string.toUpperCase());
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Nils Kenneweg
 */

/**
 * Base32 encoding/decoding
 * @namespace
 */
sjcl.codec.base32 = {
  /** The base32 alphabet.
   * @private
   */
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  _hexChars: "0123456789ABCDEFGHIJKLMNOPQRSTUV",

  /* bits in an array */
  BITS: 32,
  /* base to encode at (2^x) */
  BASE: 5,
  /* bits - base */
  REMAINING: 27,

  /** Convert from a bitArray to a base32 string. */
  fromBits: function (arr, _noEquals, _hex) {
    var BITS = sjcl.codec.base32.BITS,
      BASE = sjcl.codec.base32.BASE,
      REMAINING = sjcl.codec.base32.REMAINING;
    var out = "",
      i,
      bits = 0,
      c = sjcl.codec.base32._chars,
      ta = 0,
      bl = sjcl.bitArray.bitLength(arr);

    if (_hex) {
      c = sjcl.codec.base32._hexChars;
    }

    for (i = 0; out.length * BASE < bl; ) {
      out += c.charAt((ta ^ (arr[i] >>> bits)) >>> REMAINING);
      if (bits < BASE) {
        ta = arr[i] << (BASE - bits);
        bits += REMAINING;
        i++;
      } else {
        ta <<= BASE;
        bits -= BASE;
      }
    }
    while (out.length & 7 && !_noEquals) {
      out += "=";
    }

    return out;
  },

  /** Convert from a base32 string to a bitArray */
  toBits: function (str, _hex) {
    str = str.replace(/\s|=/g, "").toUpperCase();
    var BITS = sjcl.codec.base32.BITS,
      BASE = sjcl.codec.base32.BASE,
      REMAINING = sjcl.codec.base32.REMAINING;
    var out = [],
      i,
      bits = 0,
      c = sjcl.codec.base32._chars,
      ta = 0,
      x,
      format = "base32";

    if (_hex) {
      c = sjcl.codec.base32._hexChars;
      format = "base32hex";
    }

    for (i = 0; i < str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        // Invalid character, try hex format
        if (!_hex) {
          try {
            return sjcl.codec.base32hex.toBits(str);
          } catch (e) {}
        }
        throw new sjcl.exception.invalid("this isn't " + format + "!");
      }
      if (bits > REMAINING) {
        bits -= REMAINING;
        out.push(ta ^ (x >>> bits));
        ta = x << (BITS - bits);
      } else {
        bits += BASE;
        ta ^= x << (BITS - bits);
      }
    }
    if (bits & 56) {
      out.push(sjcl.bitArray.partial(bits & 56, ta, 1));
    }
    return out;
  }
};

sjcl.codec.base32hex = {
  fromBits: function (arr, _noEquals) {
    return sjcl.codec.base32.fromBits(arr, _noEquals, 1);
  },
  toBits: function (str) {
    return sjcl.codec.base32.toBits(str, 1);
  }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Base64 encoding/decoding
 * @namespace
 */
sjcl.codec.base64 = {
  /** The base64 alphabet.
   * @private
   */
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",

  /** Convert from a bitArray to a base64 string. */
  fromBits: function (arr, _noEquals, _url) {
    var out = "",
      i,
      bits = 0,
      c = sjcl.codec.base64._chars,
      ta = 0,
      bl = sjcl.bitArray.bitLength(arr);
    if (_url) {
      c = c.substr(0, 62) + "-_";
    }
    for (i = 0; out.length * 6 < bl; ) {
      out += c.charAt((ta ^ (arr[i] >>> bits)) >>> 26);
      if (bits < 6) {
        ta = arr[i] << (6 - bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }
    while (out.length & 3 && !_noEquals) {
      out += "=";
    }
    return out;
  },

  /** Convert from a base64 string to a bitArray */
  toBits: function (str, _url) {
    str = str.replace(/\s|=/g, "");
    var out = [],
      i,
      bits = 0,
      c = sjcl.codec.base64._chars,
      ta = 0,
      x;
    if (_url) {
      c = c.substr(0, 62) + "-_";
    }
    for (i = 0; i < str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base64!");
      }
      if (bits > 26) {
        bits -= 26;
        out.push(ta ^ (x >>> bits));
        ta = x << (32 - bits);
      } else {
        bits += 6;
        ta ^= x << (32 - bits);
      }
    }
    if (bits & 56) {
      out.push(sjcl.bitArray.partial(bits & 56, ta, 1));
    }
    return out;
  }
};

sjcl.codec.base64url = {
  fromBits: function (arr) {
    return sjcl.codec.base64.fromBits(arr, 1, 1);
  },
  toBits: function (str) {
    return sjcl.codec.base64.toBits(str, 1);
  }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Arrays of bytes
 * @namespace
 */
sjcl.codec.bytes = {
  /** Convert from a bitArray to an array of bytes. */
  fromBits: function (arr) {
    var out = [],
      bl = sjcl.bitArray.bitLength(arr),
      i,
      tmp;
    for (i = 0; i < bl / 8; i++) {
      if ((i & 3) === 0) {
        tmp = arr[i / 4];
      }
      out.push(tmp >>> 24);
      tmp <<= 8;
    }
    return out;
  },
  /** Convert from an array of bytes to a bitArray. */
  toBits: function (bytes) {
    var out = [],
      i,
      tmp = 0;
    for (i = 0; i < bytes.length; i++) {
      tmp = (tmp << 8) | bytes[i];
      if ((i & 3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i & 3) {
      out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
    }
    return out;
  }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Hexadecimal
 * @namespace
 */
sjcl.codec.hex = {
  /** Convert from a bitArray to a hex string. */
  fromBits: function (arr) {
    var out = "",
      i;
    for (i = 0; i < arr.length; i++) {
      out += ((arr[i] | 0) + 0xf00000000000).toString(16).substr(4);
    }
    return out.substr(0, sjcl.bitArray.bitLength(arr) / 4); //.replace(/(.{8})/g, "$1 ");
  },
  /** Convert from a hex string to a bitArray. */
  toBits: function (str) {
    var i,
      out = [],
      len;
    str = str.replace(/\s|0x/g, "");
    len = str.length;
    str = str + "00000000";
    for (i = 0; i < str.length; i += 8) {
      out.push(parseInt(str.substr(i, 8), 16) ^ 0);
    }
    return sjcl.bitArray.clamp(out, len * 4);
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * UTF-8 strings
 * @namespace
 */
sjcl.codec.utf8String = {
  /** Convert from a bitArray to a UTF-8 string. */
  fromBits: function (arr) {
    var out = "",
      bl = sjcl.bitArray.bitLength(arr),
      i,
      tmp;
    for (i = 0; i < bl / 8; i++) {
      if ((i & 3) === 0) {
        tmp = arr[i / 4];
      }
      out += String.fromCharCode(((tmp >>> 8) >>> 8) >>> 8);
      tmp <<= 8;
    }
    return decodeURIComponent(escape(out));
  },

  /** Convert from a UTF-8 string to a bitArray. */
  toBits: function (str) {
    str = unescape(encodeURIComponent(str));
    var out = [],
      i,
      tmp = 0;
    for (i = 0; i < str.length; i++) {
      tmp = (tmp << 8) | str.charCodeAt(i);
      if ((i & 3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i & 3) {
      out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
    }
    return out;
  }
};
/**
 * @fileOverview    Z85 codec implementation.
 * @summary         Z85 encoding is the "string-safe" ZeroMQ variant of Base85
 *                  encoding. The character set avoids the single and double
 *                  quotes and the backslash, making the encoded string
 *                  safe to embed in command-line interpreters.
 *                  Base85 uses 5 characters to encode 4 bytes of data,
 *                  making the encoded size 1/4 larger than the original;
 *                  this also makes it more efficient than uuencode or Base64,
 *                  which uses 4 characters to encode 3 bytes of data, making
 *                  the encoded size 1/3 larger than the original.
 *
 * @author          Manjul Apratim
 */

/**
 * Z85 encoding/decoding
 * http://rfc.zeromq.org/spec:32/Z85/
 * @namespace
 */
sjcl.codec.z85 = {
  /** The Z85 alphabet.
   * @private
   */
  _chars:
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#",

  /** The decoder map (maps base 85 to base 256).
   * @private
   */
  _byteMap: [
    0x00,
    0x44,
    0x00,
    0x54,
    0x53,
    0x52,
    0x48,
    0x00,
    0x4b,
    0x4c,
    0x46,
    0x41,
    0x00,
    0x3f,
    0x3e,
    0x45,
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x40,
    0x00,
    0x49,
    0x42,
    0x4a,
    0x47,
    0x51,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0x29,
    0x2a,
    0x2b,
    0x2c,
    0x2d,
    0x2e,
    0x2f,
    0x30,
    0x31,
    0x32,
    0x33,
    0x34,
    0x35,
    0x36,
    0x37,
    0x38,
    0x39,
    0x3a,
    0x3b,
    0x3c,
    0x3d,
    0x4d,
    0x00,
    0x4e,
    0x43,
    0x00,
    0x00,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    0x20,
    0x21,
    0x22,
    0x23,
    0x4f,
    0x00,
    0x50,
    0x00,
    0x00
  ],

  /**
   * @summary Method to convert a bitArray to a Z85-encoded string.
   *          The bits represented by the array MUST be multiples of 4 bytes.
   * @param   {bitArray} arr - The input bitArray.
   * @return  {string} The Z85-encoded string.
   */
  fromBits: function (arr) {
    // Sanity checks
    if (!arr) {
      return null;
    }
    // Check we have multiples of 4 bytes (32 bits)
    if (0 !== sjcl.bitArray.bitLength(arr) % 32) {
      throw new sjcl.exception.invalid("Invalid bitArray length!");
    }

    var out = "",
      c = sjcl.codec.z85._chars;

    // Convert sequences of 4 bytes (each word) to 5 characters.
    for (var i = 0; i < arr.length; ++i) {
      // Each element in the bitArray is a 32-bit (4-byte) word.
      var word = arr[i];
      var value = 0;
      for (var j = 0; j < 4; ++j) {
        // Extract each successive byte from the word from the left.
        var byteChunk = (word >>> (8 * (4 - j - 1))) & 0xff;
        // Accumulate in base-256
        value = value * 256 + byteChunk;
      }
      var divisor = 85 * 85 * 85 * 85;
      while (divisor) {
        out += c.charAt(Math.floor(value / divisor) % 85);
        divisor = Math.floor(divisor / 85);
      }
    }

    // Sanity check - each 4-bytes (1 word) should yield 5 characters.
    var encodedSize = arr.length * 5;
    if (out.length !== encodedSize) {
      throw new sjcl.exception.invalid("Bad Z85 conversion!");
    }
    return out;
  },

  /**
   * @summary Method to convert a Z85-encoded string to a bitArray.
   *          The length of the string MUST be a multiple of 5
   *          (else it is not a valid Z85 string).
   * @param   {string} str - A valid Z85-encoded string.
   * @return  {bitArray} The decoded data represented as a bitArray.
   */
  toBits: function (str) {
    // Sanity check
    if (!str) {
      return [];
    }
    // Accept only strings bounded to 5 bytes
    if (0 !== str.length % 5) {
      throw new sjcl.exception.invalid("Invalid Z85 string!");
    }

    var out = [],
      value = 0,
      byteMap = sjcl.codec.z85._byteMap;
    var word = 0,
      wordSize = 0;
    for (var i = 0; i < str.length; ) {
      // Accumulate value in base 85.
      value = value * 85 + byteMap[str[i++].charCodeAt(0) - 32];
      if (0 === i % 5) {
        // Output value in base-256
        var divisor = 256 * 256 * 256;
        while (divisor) {
          // The following is equivalent to a left shift by 8 bits
          // followed by OR-ing; however, left shift may cause sign problems
          // due to 2's complement interpretation,
          // and we're operating on unsigned values.
          word = word * Math.pow(2, 8) + (Math.floor(value / divisor) % 256);
          ++wordSize;
          // If 4 bytes have been acumulated, push the word into the bitArray.
          if (4 === wordSize) {
            out.push(word);
            (word = 0), (wordSize = 0);
          }
          divisor = Math.floor(divisor / 256);
        }
        value = 0;
      }
    }

    return out;
  }
};
/** @fileOverview Convenience functions centered around JSON encapsulation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * JSON encapsulation
 * @namespace
 */
sjcl.json = {
  /** Default values for encryption */
  defaults: {
    v: 1,
    iter: 10000,
    ks: 128,
    ts: 64,
    mode: "ccm",
    adata: "",
    cipher: "aes"
  },

  /** Simple encryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} plaintext The data to encrypt.
   * @param {Object} [params] The parameters including tag, iv and salt.
   * @param {Object} [rp] A returned version with filled-in parameters.
   * @return {Object} The cipher raw data.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   */
  _encrypt: function (password, plaintext, params, rp) {
    params = params || {};
    rp = rp || {};

    var j = sjcl.json,
      p = j._add({ iv: sjcl.random.randomWords(4, 0) }, j.defaults),
      tmp,
      prp,
      adata;
    j._add(p, params);
    adata = p.adata;
    if (typeof p.salt === "string") {
      p.salt = sjcl.codec.base64.toBits(p.salt);
    }
    if (typeof p.iv === "string") {
      p.iv = sjcl.codec.base64.toBits(p.iv);
    }

    if (
      !sjcl.mode[p.mode] ||
      !sjcl.cipher[p.cipher] ||
      (typeof password === "string" && p.iter <= 100) ||
      (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
      (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
      p.iv.length < 2 ||
      p.iv.length > 4
    ) {
      throw new sjcl.exception.invalid("json encrypt: invalid parameters");
    }

    if (typeof password === "string") {
      tmp = sjcl.misc.cachedPbkdf2(password, p);
      password = tmp.key.slice(0, p.ks / 32);
      p.salt = tmp.salt;
    } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.publicKey) {
      tmp = password.kem();
      p.kemtag = tmp.tag;
      password = tmp.key.slice(0, p.ks / 32);
    }
    if (typeof plaintext === "string") {
      plaintext = sjcl.codec.utf8String.toBits(plaintext);
    }
    if (typeof adata === "string") {
      p.adata = adata = sjcl.codec.utf8String.toBits(adata);
    }
    prp = new sjcl.cipher[p.cipher](password);

    /* return the json data */
    j._add(rp, p);
    rp.key = password;

    /* do the encryption */
    if (
      p.mode === "ccm" &&
      sjcl.arrayBuffer &&
      sjcl.arrayBuffer.ccm &&
      plaintext instanceof ArrayBuffer
    ) {
      p.ct = sjcl.arrayBuffer.ccm.encrypt(prp, plaintext, p.iv, adata, p.ts);
    } else {
      p.ct = sjcl.mode[p.mode].encrypt(prp, plaintext, p.iv, adata, p.ts);
    }

    //return j.encode(j._subtract(p, j.defaults));
    return p;
  },

  /** Simple encryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} plaintext The data to encrypt.
   * @param {Object} [params] The parameters including tag, iv and salt.
   * @param {Object} [rp] A returned version with filled-in parameters.
   * @return {String} The ciphertext serialized data.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   */
  encrypt: function (password, plaintext, params, rp) {
    var j = sjcl.json,
      p = j._encrypt.apply(j, arguments);
    return j.encode(p);
  },

  /** Simple decryption function.
   * @param {String|bitArray} password The password or key.
   * @param {Object} ciphertext The cipher raw data to decrypt.
   * @param {Object} [params] Additional non-default parameters.
   * @param {Object} [rp] A returned object with filled parameters.
   * @return {String} The plaintext.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
   */
  _decrypt: function (password, ciphertext, params, rp) {
    params = params || {};
    rp = rp || {};

    var j = sjcl.json,
      p = j._add(j._add(j._add({}, j.defaults), ciphertext), params, true),
      ct,
      tmp,
      prp,
      adata = p.adata;
    if (typeof p.salt === "string") {
      p.salt = sjcl.codec.base64.toBits(p.salt);
    }
    if (typeof p.iv === "string") {
      p.iv = sjcl.codec.base64.toBits(p.iv);
    }

    if (
      !sjcl.mode[p.mode] ||
      !sjcl.cipher[p.cipher] ||
      (typeof password === "string" && p.iter <= 100) ||
      (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
      (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
      !p.iv ||
      p.iv.length < 2 ||
      p.iv.length > 4
    ) {
      throw new sjcl.exception.invalid("json decrypt: invalid parameters");
    }

    if (typeof password === "string") {
      tmp = sjcl.misc.cachedPbkdf2(password, p);
      password = tmp.key.slice(0, p.ks / 32);
      p.salt = tmp.salt;
    } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.secretKey) {
      password = password
        .unkem(sjcl.codec.base64.toBits(p.kemtag))
        .slice(0, p.ks / 32);
    }
    if (typeof adata === "string") {
      adata = sjcl.codec.utf8String.toBits(adata);
    }
    prp = new sjcl.cipher[p.cipher](password);

    /* do the decryption */
    if (
      p.mode === "ccm" &&
      sjcl.arrayBuffer &&
      sjcl.arrayBuffer.ccm &&
      p.ct instanceof ArrayBuffer
    ) {
      ct = sjcl.arrayBuffer.ccm.decrypt(prp, p.ct, p.iv, p.tag, adata, p.ts);
    } else {
      ct = sjcl.mode[p.mode].decrypt(prp, p.ct, p.iv, adata, p.ts);
    }

    /* return the json data */
    j._add(rp, p);
    rp.key = password;

    if (params.raw === 1) {
      return ct;
    } else {
      return sjcl.codec.utf8String.fromBits(ct);
    }
  },

  /** Simple decryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} ciphertext The ciphertext to decrypt.
   * @param {Object} [params] Additional non-default parameters.
   * @param {Object} [rp] A returned object with filled parameters.
   * @return {String} The plaintext.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
   */
  decrypt: function (password, ciphertext, params, rp) {
    var j = sjcl.json;
    return j._decrypt(password, j.decode(ciphertext), params, rp);
  },

  /** Encode a flat structure into a JSON string.
   * @param {Object} obj The structure to encode.
   * @return {String} A JSON string.
   * @throws {sjcl.exception.invalid} if obj has a non-alphanumeric property.
   * @throws {sjcl.exception.bug} if a parameter has an unsupported type.
   */
  encode: function (obj) {
    var i,
      out = "{",
      comma = "";
    for (i in obj) {
      if (obj.hasOwnProperty(i)) {
        if (!i.match(/^[a-z0-9]+$/i)) {
          throw new sjcl.exception.invalid(
            "json encode: invalid property name"
          );
        }
        out += comma + '"' + i + '":';
        comma = ",";

        switch (typeof obj[i]) {
          case "number":
          case "boolean":
            out += obj[i];
            break;

          case "string":
            out += '"' + escape(obj[i]) + '"';
            break;

          case "object":
            out += '"' + sjcl.codec.base64.fromBits(obj[i], 0) + '"';
            break;

          default:
            throw new sjcl.exception.bug("json encode: unsupported type");
        }
      }
    }
    return out + "}";
  },

  /** Decode a simple (flat) JSON string into a structure.  The ciphertext,
   * adata, salt and iv will be base64-decoded.
   * @param {String} str The string.
   * @return {Object} The decoded structure.
   * @throws {sjcl.exception.invalid} if str isn't (simple) JSON.
   */
  decode: function (str) {
    str = str.replace(/\s/g, "");
    if (!str.match(/^\{.*\}$/)) {
      throw new sjcl.exception.invalid("json decode: this isn't json!");
    }
    var a = str.replace(/^\{|\}$/g, "").split(/,/),
      out = {},
      i,
      m;
    for (i = 0; i < a.length; i++) {
      if (
        !(m = a[i].match(
          /^\s*(?:(["']?)([a-z][a-z0-9]*)\1)\s*:\s*(?:(-?\d+)|"([a-z0-9+\/%*_.@=\-]*)"|(true|false))$/i
        ))
      ) {
        throw new sjcl.exception.invalid("json decode: this isn't json!");
      }
      if (m[3] != null) {
        out[m[2]] = parseInt(m[3], 10);
      } else if (m[4] != null) {
        out[m[2]] = m[2].match(/^(ct|adata|salt|iv)$/)
          ? sjcl.codec.base64.toBits(m[4])
          : unescape(m[4]);
      } else if (m[5] != null) {
        out[m[2]] = m[5] === "true";
      }
    }
    return out;
  },

  /** Insert all elements of src into target, modifying and returning target.
   * @param {Object} target The object to be modified.
   * @param {Object} src The object to pull data from.
   * @param {boolean} [requireSame=false] If true, throw an exception if any field of target differs from corresponding field of src.
   * @return {Object} target.
   * @private
   */
  _add: function (target, src, requireSame) {
    if (target === undefined) {
      target = {};
    }
    if (src === undefined) {
      return target;
    }
    var i;
    for (i in src) {
      if (src.hasOwnProperty(i)) {
        if (requireSame && target[i] !== undefined && target[i] !== src[i]) {
          throw new sjcl.exception.invalid("required parameter overridden");
        }
        target[i] = src[i];
      }
    }
    return target;
  },

  /** Remove all elements of minus from plus.  Does not modify plus.
   * @private
   */
  _subtract: function (plus, minus) {
    var out = {},
      i;

    for (i in plus) {
      if (plus.hasOwnProperty(i) && plus[i] !== minus[i]) {
        out[i] = plus[i];
      }
    }

    return out;
  },

  /** Return only the specified elements of src.
   * @private
   */
  _filter: function (src, filter) {
    var out = {},
      i;
    for (i = 0; i < filter.length; i++) {
      if (src[filter[i]] !== undefined) {
        out[filter[i]] = src[filter[i]];
      }
    }
    return out;
  }
};

/** Simple encryption function; convenient shorthand for sjcl.json.encrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} plaintext The data to encrypt.
 * @param {Object} [params] The parameters including tag, iv and salt.
 * @param {Object} [rp] A returned version with filled-in parameters.
 * @return {String} The ciphertext.
 */
sjcl.encrypt = sjcl.json.encrypt;

/** Simple decryption function; convenient shorthand for sjcl.json.decrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} ciphertext The ciphertext to decrypt.
 * @param {Object} [params] Additional non-default parameters.
 * @param {Object} [rp] A returned object with filled parameters.
 * @return {String} The plaintext.
 */
sjcl.decrypt = sjcl.json.decrypt;

/** The cache for cachedPbkdf2.
 * @private
 */
sjcl.misc._pbkdf2Cache = {};

/** Cached PBKDF2 key derivation.
 * @param {String} password The password.
 * @param {Object} [obj] The derivation params (iteration count and optional salt).
 * @return {Object} The derived data in key, the salt in salt.
 */
sjcl.misc.cachedPbkdf2 = function (password, obj) {
  var cache = sjcl.misc._pbkdf2Cache,
    c,
    cp,
    str,
    salt,
    iter;

  obj = obj || {};
  iter = obj.iter || 1000;

  /* open the cache for this password and iteration count */
  cp = cache[password] = cache[password] || {};
  c = cp[iter] = cp[iter] || {
    firstSalt:
      obj.salt && obj.salt.length
        ? obj.salt.slice(0)
        : sjcl.random.randomWords(2, 0)
  };

  salt = obj.salt === undefined ? c.firstSalt : obj.salt;

  c[salt] = c[salt] || sjcl.misc.pbkdf2(password, salt, obj.iter);
  return { key: c[salt].slice(0), salt: salt.slice(0) };
};
/**
 * base class for all ecc operations.
 * @namespace
 */
sjcl.ecc = {};

/**
 * Represents a point on a curve in affine coordinates.
 * @constructor
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 * @param {bigInt} x The x coordinate.
 * @param {bigInt} y The y coordinate.
 */
sjcl.ecc.point = function (curve, x, y) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    if (x instanceof sjcl.bn) {
      x = new curve.field(x);
    }
    if (y instanceof sjcl.bn) {
      y = new curve.field(y);
    }

    this.x = x;
    this.y = y;

    this.isIdentity = false;
  }
  this.curve = curve;
};

sjcl.ecc.point.prototype = {
  toJac: function () {
    return new sjcl.ecc.pointJac(
      this.curve,
      this.x,
      this.y,
      new this.curve.field(1)
    );
  },

  mult: function (k) {
    return this.toJac().mult(k, this).toAffine();
  },

  /**
   * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply this by.
   * @param {bigInt} k2 The coefficient to multiply affine2 this by.
   * @param {sjcl.ecc.point} affine The other point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
   */
  mult2: function (k, k2, affine2) {
    return this.toJac().mult2(k, this, k2, affine2).toAffine();
  },

  multiples: function () {
    var m, i, j;
    if (this._multiples === undefined) {
      j = this.toJac().doubl();
      m = this._multiples = [
        new sjcl.ecc.point(this.curve),
        this,
        j.toAffine()
      ];
      for (i = 3; i < 16; i++) {
        j = j.add(this);
        m.push(j.toAffine());
      }
    }
    return this._multiples;
  },

  negate: function () {
    var newY = new this.curve.field(0).sub(this.y).normalize().reduce();
    return new sjcl.ecc.point(this.curve, this.x, newY);
  },

  isValid: function () {
    return this.y
      .square()
      .equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
  },

  toBits: function () {
    return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
  }
};

/**
 * Represents a point on a curve in Jacobian coordinates. Coordinates can be specified as bigInts or strings (which
 * will be converted to bigInts).
 *
 * @constructor
 * @param {bigInt/string} x The x coordinate.
 * @param {bigInt/string} y The y coordinate.
 * @param {bigInt/string} z The z coordinate.
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 */
sjcl.ecc.pointJac = function (curve, x, y, z) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    this.x = x;
    this.y = y;
    this.z = z;
    this.isIdentity = false;
  }
  this.curve = curve;
};

sjcl.ecc.pointJac.prototype = {
  /**
   * Adds S and T and returns the result in Jacobian coordinates. Note that S must be in Jacobian coordinates and T must be in affine coordinates.
   * @param {sjcl.ecc.pointJac} S One of the points to add, in Jacobian coordinates.
   * @param {sjcl.ecc.point} T The other point to add, in affine coordinates.
   * @return {sjcl.ecc.pointJac} The sum of the two points, in Jacobian coordinates.
   */
  add: function (T) {
    var S = this,
      sz2,
      c,
      d,
      c2,
      x1,
      x2,
      x,
      y1,
      y2,
      y,
      z;
    if (S.curve !== T.curve) {
      throw new sjcl.exception.invalid(
        "sjcl.ecc.add(): Points must be on the same curve to add them!"
      );
    }

    if (S.isIdentity) {
      return T.toJac();
    } else if (T.isIdentity) {
      return S;
    }

    sz2 = S.z.square();
    c = T.x.mul(sz2).subM(S.x);

    if (c.equals(0)) {
      if (S.y.equals(T.y.mul(sz2.mul(S.z)))) {
        // same point
        return S.doubl();
      } else {
        // inverses
        return new sjcl.ecc.pointJac(S.curve);
      }
    }

    d = T.y.mul(sz2.mul(S.z)).subM(S.y);
    c2 = c.square();

    x1 = d.square();
    x2 = c.square().mul(c).addM(S.x.add(S.x).mul(c2));
    x = x1.subM(x2);

    y1 = S.x.mul(c2).subM(x).mul(d);
    y2 = S.y.mul(c.square().mul(c));
    y = y1.subM(y2);

    z = S.z.mul(c);

    return new sjcl.ecc.pointJac(this.curve, x, y, z);
  },

  /**
   * doubles this point.
   * @return {sjcl.ecc.pointJac} The doubled point.
   */
  doubl: function () {
    if (this.isIdentity) {
      return this;
    }

    var y2 = this.y.square(),
      a = y2.mul(this.x.mul(4)),
      b = y2.square().mul(8),
      z2 = this.z.square(),
      c =
        this.curve.a.toString() == new sjcl.bn(-3).toString()
          ? this.x.sub(z2).mul(3).mul(this.x.add(z2))
          : this.x.square().mul(3).add(z2.square().mul(this.curve.a)),
      x = c.square().subM(a).subM(a),
      y = a.sub(x).mul(c).subM(b),
      z = this.y.add(this.y).mul(this.z);
    return new sjcl.ecc.pointJac(this.curve, x, y, z);
  },

  /**
   * Returns a copy of this point converted to affine coordinates.
   * @return {sjcl.ecc.point} The converted point.
   */
  toAffine: function () {
    if (this.isIdentity || this.z.equals(0)) {
      return new sjcl.ecc.point(this.curve);
    }
    var zi = this.z.inverse(),
      zi2 = zi.square();
    return new sjcl.ecc.point(
      this.curve,
      this.x.mul(zi2).fullReduce(),
      this.y.mul(zi2.mul(zi)).fullReduce()
    );
  },

  /**
   * Multiply this point by k and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply by.
   * @param {sjcl.ecc.point} affine This point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication, in Jacobian coordinates.
   */
  mult: function (k, affine) {
    if (typeof k === "number") {
      k = [k];
    } else if (k.limbs !== undefined) {
      k = k.normalize().limbs;
    }

    var i,
      j,
      out = new sjcl.ecc.point(this.curve).toJac(),
      multiples = affine.multiples();

    for (i = k.length - 1; i >= 0; i--) {
      for (j = sjcl.bn.prototype.radix - 4; j >= 0; j -= 4) {
        out = out
          .doubl()
          .doubl()
          .doubl()
          .doubl()
          .add(multiples[(k[i] >> j) & 0xf]);
      }
    }

    return out;
  },

  /**
   * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply this by.
   * @param {sjcl.ecc.point} affine This point in affine coordinates.
   * @param {bigInt} k2 The coefficient to multiply affine2 this by.
   * @param {sjcl.ecc.point} affine The other point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
   */
  mult2: function (k1, affine, k2, affine2) {
    if (typeof k1 === "number") {
      k1 = [k1];
    } else if (k1.limbs !== undefined) {
      k1 = k1.normalize().limbs;
    }

    if (typeof k2 === "number") {
      k2 = [k2];
    } else if (k2.limbs !== undefined) {
      k2 = k2.normalize().limbs;
    }

    var i,
      j,
      out = new sjcl.ecc.point(this.curve).toJac(),
      m1 = affine.multiples(),
      m2 = affine2.multiples(),
      l1,
      l2;

    for (i = Math.max(k1.length, k2.length) - 1; i >= 0; i--) {
      l1 = k1[i] | 0;
      l2 = k2[i] | 0;
      for (j = sjcl.bn.prototype.radix - 4; j >= 0; j -= 4) {
        out = out
          .doubl()
          .doubl()
          .doubl()
          .doubl()
          .add(m1[(l1 >> j) & 0xf])
          .add(m2[(l2 >> j) & 0xf]);
      }
    }

    return out;
  },

  negate: function () {
    return this.toAffine().negate().toJac();
  },

  isValid: function () {
    var z2 = this.z.square(),
      z4 = z2.square(),
      z6 = z4.mul(z2);
    return this.y
      .square()
      .equals(
        this.curve.b
          .mul(z6)
          .add(this.x.mul(this.curve.a.mul(z4).add(this.x.square())))
      );
  }
};

/**
 * Construct an elliptic curve. Most users will not use this and instead start with one of the NIST curves defined below.
 *
 * @constructor
 * @param {bigInt} p The prime modulus.
 * @param {bigInt} r The prime order of the curve.
 * @param {bigInt} a The constant a in the equation of the curve y^2 = x^3 + ax + b (for NIST curves, a is always -3).
 * @param {bigInt} x The x coordinate of a base point of the curve.
 * @param {bigInt} y The y coordinate of a base point of the curve.
 */
sjcl.ecc.curve = function (Field, r, a, b, x, y) {
  this.field = Field;
  this.r = new sjcl.bn(r);
  this.a = new Field(a);
  this.b = new Field(b);
  this.G = new sjcl.ecc.point(this, new Field(x), new Field(y));
};

sjcl.ecc.curve.prototype.fromBits = function (bits) {
  var w = sjcl.bitArray,
    l = (this.field.prototype.exponent + 7) & -8,
    p = new sjcl.ecc.point(
      this,
      this.field.fromBits(w.bitSlice(bits, 0, l)),
      this.field.fromBits(w.bitSlice(bits, l, 2 * l))
    );
  if (!p.isValid()) {
    throw new sjcl.exception.corrupt("not on the curve!");
  }
  return p;
};

sjcl.ecc.curves = {
  c192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192,
    "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",
    -3,
    "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
  ),

  c224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224,
    "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
    -3,
    "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"
  ),

  c256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256,
    "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    -3,
    "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
  ),

  c384: new sjcl.ecc.curve(
    sjcl.bn.prime.p384,
    "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    -3,
    "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
  ),

  c521: new sjcl.ecc.curve(
    sjcl.bn.prime.p521,
    "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    -3,
    "0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    "0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
    "0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"
  ),

  k192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192k,
    "0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d",
    0,
    3,
    "0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
    "0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"
  ),

  k224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224k,
    "0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
    0,
    5,
    "0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
    "0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5"
  ),

  k256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256k,
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    0,
    7,
    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  )
};

sjcl.ecc.curveName = function (curve) {
  var curcurve;
  for (curcurve in sjcl.ecc.curves) {
    if (sjcl.ecc.curves.hasOwnProperty(curcurve)) {
      if (sjcl.ecc.curves[curcurve] === curve) {
        return curcurve;
      }
    }
  }

  throw new sjcl.exception.invalid("no such curve");
};

sjcl.ecc.deserialize = function (key) {
  var types = ["elGamal", "ecdsa"];

  if (!key || !key.curve || !sjcl.ecc.curves[key.curve]) {
    throw new sjcl.exception.invalid("invalid serialization");
  }
  if (types.indexOf(key.type) === -1) {
    throw new sjcl.exception.invalid("invalid type");
  }

  var curve = sjcl.ecc.curves[key.curve];

  if (key.secretKey) {
    if (!key.exponent) {
      throw new sjcl.exception.invalid("invalid exponent");
    }
    var exponent = new sjcl.bn(key.exponent);
    return new sjcl.ecc[key.type].secretKey(curve, exponent);
  } else {
    if (!key.point) {
      throw new sjcl.exception.invalid("invalid point");
    }

    var point = curve.fromBits(sjcl.codec.hex.toBits(key.point));
    return new sjcl.ecc[key.type].publicKey(curve, point);
  }
};

/** our basicKey classes
 */
sjcl.ecc.basicKey = {
  /** ecc publicKey.
   * @constructor
   * @param {curve} curve the elliptic curve
   * @param {point} point the point on the curve
   */
  publicKey: function (curve, point) {
    this._curve = curve;
    this._curveBitLength = curve.r.bitLength();
    if (point instanceof Array) {
      this._point = curve.fromBits(point);
    } else {
      this._point = point;
    }

    this.serialize = function () {
      var curveName = sjcl.ecc.curveName(curve);
      return {
        type: this.getType(),
        secretKey: false,
        point: sjcl.codec.hex.fromBits(this._point.toBits()),
        curve: curveName
      };
    };

    /** get this keys point data
     * @return x and y as bitArrays
     */
    this.get = function () {
      var pointbits = this._point.toBits();
      var len = sjcl.bitArray.bitLength(pointbits);
      var x = sjcl.bitArray.bitSlice(pointbits, 0, len / 2);
      var y = sjcl.bitArray.bitSlice(pointbits, len / 2);
      return { x: x, y: y };
    };
  },

  /** ecc secretKey
   * @constructor
   * @param {curve} curve the elliptic curve
   * @param exponent
   */
  secretKey: function (curve, exponent) {
    this._curve = curve;
    this._curveBitLength = curve.r.bitLength();
    this._exponent = exponent;

    this.serialize = function () {
      var exponent = this.get();
      var curveName = sjcl.ecc.curveName(curve);
      return {
        type: this.getType(),
        secretKey: true,
        exponent: sjcl.codec.hex.fromBits(exponent),
        curve: curveName
      };
    };

    /** get this keys exponent data
     * @return {bitArray} exponent
     */
    this.get = function () {
      return this._exponent.toBits();
    };
  }
};

/** @private */
sjcl.ecc.basicKey.generateKeys = function (cn) {
  return function generateKeys(curve, paranoia, sec) {
    curve = curve || 256;

    if (typeof curve === "number") {
      curve = sjcl.ecc.curves["c" + curve];
      if (curve === undefined) {
        throw new sjcl.exception.invalid("no such curve");
      }
    }
    sec = sec || sjcl.bn.random(curve.r, paranoia);

    var pub = curve.G.mult(sec);
    return {
      pub: new sjcl.ecc[cn].publicKey(curve, pub),
      sec: new sjcl.ecc[cn].secretKey(curve, sec)
    };
  };
};

/** elGamal keys */
sjcl.ecc.elGamal = {
  /** generate keys
   * @function
   * @param curve
   * @param {int} paranoia Paranoia for generation (default 6)
   * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
   */
  generateKeys: sjcl.ecc.basicKey.generateKeys("elGamal"),
  /** elGamal publicKey.
   * @constructor
   * @augments sjcl.ecc.basicKey.publicKey
   */
  publicKey: function (curve, point) {
    sjcl.ecc.basicKey.publicKey.apply(this, arguments);
  },
  /** elGamal secretKey
   * @constructor
   * @augments sjcl.ecc.basicKey.secretKey
   */
  secretKey: function (curve, exponent) {
    sjcl.ecc.basicKey.secretKey.apply(this, arguments);
  }
};

sjcl.ecc.elGamal.publicKey.prototype = {
  /** Kem function of elGamal Public Key
   * @param paranoia paranoia to use for randomization.
   * @return {object} key and tag. unkem(tag) with the corresponding secret key results in the key returned.
   */
  kem: function (paranoia) {
    var sec = sjcl.bn.random(this._curve.r, paranoia),
      tag = this._curve.G.mult(sec).toBits(),
      key = sjcl.hash.sha256.hash(this._point.mult(sec).toBits());
    return { key: key, tag: tag };
  },

  getType: function () {
    return "elGamal";
  }
};

sjcl.ecc.elGamal.secretKey.prototype = {
  /** UnKem function of elGamal Secret Key
   * @param {bitArray} tag The Tag to decrypt.
   * @return {bitArray} decrypted key.
   */
  unkem: function (tag) {
    return sjcl.hash.sha256.hash(
      this._curve.fromBits(tag).mult(this._exponent).toBits()
    );
  },

  /** Diffie-Hellmann function
   * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
   * @return {bitArray} diffie-hellmann result for this key combination.
   */
  dh: function (pk) {
    return sjcl.hash.sha256.hash(pk._point.mult(this._exponent).toBits());
  },

  /** Diffie-Hellmann function, compatible with Java generateSecret
   * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
   * @return {bitArray} undigested X value, diffie-hellmann result for this key combination,
   * compatible with Java generateSecret().
   */
  dhJavaEc: function (pk) {
    return pk._point.mult(this._exponent).x.toBits();
  },

  getType: function () {
    return "elGamal";
  }
};

/** ecdsa keys */
sjcl.ecc.ecdsa = {
  /** generate keys
   * @function
   * @param curve
   * @param {int} paranoia Paranoia for generation (default 6)
   * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
   */
  generateKeys: sjcl.ecc.basicKey.generateKeys("ecdsa")
};

/** ecdsa publicKey.
 * @constructor
 * @augments sjcl.ecc.basicKey.publicKey
 */
sjcl.ecc.ecdsa.publicKey = function (curve, point) {
  sjcl.ecc.basicKey.publicKey.apply(this, arguments);
};

/** specific functions for ecdsa publicKey. */
sjcl.ecc.ecdsa.publicKey.prototype = {
  /** Diffie-Hellmann function
   * @param {bitArray} hash hash to verify.
   * @param {bitArray} rs signature bitArray.
   * @param {boolean}  fakeLegacyVersion use old legacy version
   */
  verify: function (hash, rs, fakeLegacyVersion) {
    if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
      hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
    }
    var w = sjcl.bitArray,
      R = this._curve.r,
      l = this._curveBitLength,
      r = sjcl.bn.fromBits(w.bitSlice(rs, 0, l)),
      ss = sjcl.bn.fromBits(w.bitSlice(rs, l, 2 * l)),
      s = fakeLegacyVersion ? ss : ss.inverseMod(R),
      hG = sjcl.bn.fromBits(hash).mul(s).mod(R),
      hA = r.mul(s).mod(R),
      r2 = this._curve.G.mult2(hG, hA, this._point).x;
    if (
      r.equals(0) ||
      ss.equals(0) ||
      r.greaterEquals(R) ||
      ss.greaterEquals(R) ||
      !r2.equals(r)
    ) {
      if (fakeLegacyVersion === undefined) {
        return this.verify(hash, rs, true);
      } else {
        throw new sjcl.exception.corrupt("signature didn't check out");
      }
    }
    return true;
  },

  getType: function () {
    return "ecdsa";
  }
};

/** ecdsa secretKey
 * @constructor
 * @augments sjcl.ecc.basicKey.publicKey
 */
sjcl.ecc.ecdsa.secretKey = function (curve, exponent) {
  sjcl.ecc.basicKey.secretKey.apply(this, arguments);
};

/** specific functions for ecdsa secretKey. */
sjcl.ecc.ecdsa.secretKey.prototype = {
  /** Diffie-Hellmann function
   * @param {bitArray} hash hash to sign.
   * @param {int} paranoia paranoia for random number generation
   * @param {boolean} fakeLegacyVersion use old legacy version
   */
  sign: function (hash, paranoia, fakeLegacyVersion, fixedKForTesting) {
    if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
      hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
    }
    var R = this._curve.r,
      l = R.bitLength(),
      k = fixedKForTesting || sjcl.bn.random(R.sub(1), paranoia).add(1),
      r = this._curve.G.mult(k).x.mod(R),
      ss = sjcl.bn.fromBits(hash).add(r.mul(this._exponent)),
      s = fakeLegacyVersion
        ? ss.inverseMod(R).mul(k).mod(R)
        : ss.mul(k.inverseMod(R)).mod(R);
    return sjcl.bitArray.concat(r.toBits(l), s.toBits(l));
  },

  getType: function () {
    return "ecdsa";
  }
};
if (typeof module !== "undefined" && module.exports) {
  module.exports = sjcl;
}
if (typeof define === "function") {
  define([], function () {
    return sjcl;
  });
}
/** @fileOverview HKDF implementation.
 *
 * @author Steve Thomas
 */

/** HKDF with the specified hash function.
 * @param {bitArray} ikm The input keying material.
 * @param {Number} keyBitLength The output key length, in bits.
 * @param {String|bitArray} salt The salt for HKDF.
 * @param {String|bitArray} info The info for HKDF.
 * @param {Object} [Hash=sjcl.hash.sha256] The hash function to use.
 * @return {bitArray} derived key.
 */
sjcl.misc.hkdf = function (ikm, keyBitLength, salt, info, Hash) {
  var hmac,
    key,
    i,
    hashLen,
    loops,
    curOut,
    ret = [];

  Hash = Hash || sjcl.hash.sha256;
  if (typeof info === "string") {
    info = sjcl.codec.utf8String.toBits(info);
  }
  if (typeof salt === "string") {
    salt = sjcl.codec.utf8String.toBits(salt);
  } else if (!salt) {
    salt = [];
  }

  hmac = new sjcl.misc.hmac(salt, Hash);
  key = hmac.mac(ikm);
  hashLen = sjcl.bitArray.bitLength(key);

  loops = Math.ceil(keyBitLength / hashLen);
  if (loops > 255) {
    throw new sjcl.exception.invalid("key bit length is too large for hkdf");
  }

  hmac = new sjcl.misc.hmac(key, Hash);
  curOut = [];
  for (i = 1; i <= loops; i++) {
    hmac.update(curOut);
    hmac.update(info);
    hmac.update([sjcl.bitArray.partial(8, i)]);
    curOut = hmac.digest();
    ret = sjcl.bitArray.concat(ret, curOut);
  }
  return sjcl.bitArray.clamp(ret, keyBitLength);
};
/** @fileOverview HMAC implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** HMAC with the specified hash function.
 * @constructor
 * @param {bitArray} key the key for HMAC.
 * @param {Object} [Hash=sjcl.hash.sha256] The hash function to use.
 */
sjcl.misc.hmac = function (key, Hash) {
  this._hash = Hash = Hash || sjcl.hash.sha256;
  var exKey = [[], []],
    i,
    bs = Hash.prototype.blockSize / 32;
  this._baseHash = [new Hash(), new Hash()];

  if (key.length > bs) {
    key = Hash.hash(key);
  }

  for (i = 0; i < bs; i++) {
    exKey[0][i] = key[i] ^ 0x36363636;
    exKey[1][i] = key[i] ^ 0x5c5c5c5c;
  }

  console.log("keys", exKey);

  this._baseHash[0].update(exKey[0]);
  this._baseHash[1].update(exKey[1]);
  this._resultHash = new Hash(this._baseHash[0]);
};

/** HMAC with the specified hash function.  Also called encrypt since it's a prf.
 * @param {bitArray|String} data The data to mac.
 */
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (
  data
) {
  if (!this._updated) {
    this.update(data);
    return this.digest(data);
  } else {
    throw new sjcl.exception.invalid("encrypt on already updated hmac called!");
  }
};

sjcl.misc.hmac.prototype.reset = function () {
  this._resultHash = new this._hash(this._baseHash[0]);
  this._updated = false;
};

sjcl.misc.hmac.prototype.update = function (data) {
  this._updated = true;
  this._resultHash.update(data);
};

sjcl.misc.hmac.prototype.digest = function () {
  var w = this._resultHash.finalize(),
    result = new this._hash(this._baseHash[1]).update(w).finalize();

  this.reset();

  return result;
};
/** @fileOverview OCB 2.0 implementation
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Phil Rogaway's Offset CodeBook mode, version 2.0.
 * May be covered by US and international patents.
 *
 * @namespace
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
sjcl.mode.ocb2 = {
  /** The name of the mode.
   * @constant
   */
  name: "ocb2",

  /** Encrypt in OCB mode, version 2.0.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=64] the desired tag length, in bits.
   * @param {boolean} [premac=false] true if the authentication data is pre-macced with PMAC.
   * @return The encrypted data, an array of bytes.
   * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits.
   */
  encrypt: function (prp, plaintext, iv, adata, tlen, premac) {
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("ocb iv must be 128 bits");
    }
    var i,
      times2 = sjcl.mode.ocb2._times2,
      w = sjcl.bitArray,
      xor = w._xor4,
      checksum = [0, 0, 0, 0],
      delta = times2(prp.encrypt(iv)),
      bi,
      bl,
      output = [],
      pad;

    adata = adata || [];
    tlen = tlen || 64;

    for (i = 0; i + 4 < plaintext.length; i += 4) {
      /* Encrypt a non-final block */
      bi = plaintext.slice(i, i + 4);
      checksum = xor(checksum, bi);
      output = output.concat(xor(delta, prp.encrypt(xor(delta, bi))));
      delta = times2(delta);
    }

    /* Chop out the final block */
    bi = plaintext.slice(i);
    bl = w.bitLength(bi);
    pad = prp.encrypt(xor(delta, [0, 0, 0, bl]));
    bi = w.clamp(xor(bi.concat([0, 0, 0]), pad), bl);

    /* Checksum the final block, and finalize the checksum */
    checksum = xor(checksum, xor(bi.concat([0, 0, 0]), pad));
    checksum = prp.encrypt(xor(checksum, xor(delta, times2(delta))));

    /* MAC the header */
    if (adata.length) {
      checksum = xor(
        checksum,
        premac ? adata : sjcl.mode.ocb2.pmac(prp, adata)
      );
    }

    return output.concat(w.concat(bi, w.clamp(checksum, tlen)));
  },

  /** Decrypt in OCB mode.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=64] the desired tag length, in bits.
   * @param {boolean} [premac=false] true if the authentication data is pre-macced with PMAC.
   * @return The decrypted data, an array of bytes.
   * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits.
   * @throws {sjcl.exception.corrupt} if if the message is corrupt.
   */
  decrypt: function (prp, ciphertext, iv, adata, tlen, premac) {
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("ocb iv must be 128 bits");
    }
    tlen = tlen || 64;
    var i,
      times2 = sjcl.mode.ocb2._times2,
      w = sjcl.bitArray,
      xor = w._xor4,
      checksum = [0, 0, 0, 0],
      delta = times2(prp.encrypt(iv)),
      bi,
      bl,
      len = sjcl.bitArray.bitLength(ciphertext) - tlen,
      output = [],
      pad;

    adata = adata || [];

    for (i = 0; i + 4 < len / 32; i += 4) {
      /* Decrypt a non-final block */
      bi = xor(delta, prp.decrypt(xor(delta, ciphertext.slice(i, i + 4))));
      checksum = xor(checksum, bi);
      output = output.concat(bi);
      delta = times2(delta);
    }

    /* Chop out and decrypt the final block */
    bl = len - i * 32;
    pad = prp.encrypt(xor(delta, [0, 0, 0, bl]));
    bi = xor(pad, w.clamp(ciphertext.slice(i), bl).concat([0, 0, 0]));

    /* Checksum the final block, and finalize the checksum */
    checksum = xor(checksum, bi);
    checksum = prp.encrypt(xor(checksum, xor(delta, times2(delta))));

    /* MAC the header */
    if (adata.length) {
      checksum = xor(
        checksum,
        premac ? adata : sjcl.mode.ocb2.pmac(prp, adata)
      );
    }

    if (!w.equal(w.clamp(checksum, tlen), w.bitSlice(ciphertext, len))) {
      throw new sjcl.exception.corrupt("ocb: tag doesn't match");
    }

    return output.concat(w.clamp(bi, bl));
  },

  /** PMAC authentication for OCB associated data.
   * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
   * @param {bitArray} adata The authenticated data.
   */
  pmac: function (prp, adata) {
    var i,
      times2 = sjcl.mode.ocb2._times2,
      w = sjcl.bitArray,
      xor = w._xor4,
      checksum = [0, 0, 0, 0],
      delta = prp.encrypt([0, 0, 0, 0]),
      bi;

    delta = xor(delta, times2(times2(delta)));

    for (i = 0; i + 4 < adata.length; i += 4) {
      delta = times2(delta);
      checksum = xor(checksum, prp.encrypt(xor(delta, adata.slice(i, i + 4))));
    }

    bi = adata.slice(i);
    if (w.bitLength(bi) < 128) {
      delta = xor(delta, times2(delta));
      bi = w.concat(bi, [0x80000000 | 0, 0, 0, 0]);
    }
    checksum = xor(checksum, bi);
    return prp.encrypt(xor(times2(xor(delta, times2(delta))), checksum));
  },

  /** Double a block of words, OCB style.
   * @private
   */
  _times2: function (x) {
    return [
      (x[0] << 1) ^ (x[1] >>> 31),
      (x[1] << 1) ^ (x[2] >>> 31),
      (x[2] << 1) ^ (x[3] >>> 31),
      (x[3] << 1) ^ ((x[0] >>> 31) * 0x87)
    ];
  }
};
/**
 * OCB2.0 implementation slightly modified by Yifan Gu
 * to support progressive encryption
 * @author Yifan Gu
 */

/** @fileOverview OCB 2.0 implementation
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Phil Rogaway's Offset CodeBook mode, version 2.0.
 * May be covered by US and international patents.
 *
 * @namespace
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

sjcl.mode.ocb2progressive = {
  createEncryptor: function (prp, iv, adata, tlen, premac) {
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("ocb iv must be 128 bits");
    }
    var i,
      times2 = sjcl.mode.ocb2._times2,
      w = sjcl.bitArray,
      xor = w._xor4,
      checksum = [0, 0, 0, 0],
      delta = times2(prp.encrypt(iv)),
      bi,
      bl,
      datacache = [],
      pad;

    adata = adata || [];
    tlen = tlen || 64;

    return {
      process: function (data) {
        var datalen = sjcl.bitArray.bitLength(data);
        if (datalen == 0) {
          // empty input natrually gives empty output
          return [];
        }
        var output = [];
        datacache = datacache.concat(data);
        for (i = 0; i + 4 < datacache.length; i += 4) {
          /* Encrypt a non-final block */
          bi = datacache.slice(i, i + 4);
          checksum = xor(checksum, bi);
          output = output.concat(xor(delta, prp.encrypt(xor(delta, bi))));
          delta = times2(delta);
        }
        datacache = datacache.slice(i); // at end of each process we ensure size of datacache is smaller than 4
        return output; //spits out the result.
      },
      finalize: function () {
        // the final block
        bi = datacache;
        bl = w.bitLength(bi);
        pad = prp.encrypt(xor(delta, [0, 0, 0, bl]));
        bi = w.clamp(xor(bi.concat([0, 0, 0]), pad), bl);

        /* Checksum the final block, and finalize the checksum */
        checksum = xor(checksum, xor(bi.concat([0, 0, 0]), pad));
        checksum = prp.encrypt(xor(checksum, xor(delta, times2(delta))));

        /* MAC the header */
        if (adata.length) {
          checksum = xor(
            checksum,
            premac ? adata : sjcl.mode.ocb2.pmac(prp, adata)
          );
        }

        return w.concat(bi, w.clamp(checksum, tlen)); // spits out the last block
      }
    };
  },
  createDecryptor: function (prp, iv, adata, tlen, premac) {
    if (sjcl.bitArray.bitLength(iv) !== 128) {
      throw new sjcl.exception.invalid("ocb iv must be 128 bits");
    }
    tlen = tlen || 64;
    var i,
      times2 = sjcl.mode.ocb2._times2,
      w = sjcl.bitArray,
      xor = w._xor4,
      checksum = [0, 0, 0, 0],
      delta = times2(prp.encrypt(iv)),
      bi,
      bl,
      datacache = [],
      pad;

    adata = adata || [];

    return {
      process: function (data) {
        if (data.length == 0) {
          // empty input natrually gives empty output
          return [];
        }
        var output = [];
        datacache = datacache.concat(data);
        var cachelen = sjcl.bitArray.bitLength(datacache);
        for (i = 0; i + 4 < (cachelen - tlen) / 32; i += 4) {
          /* Decrypt a non-final block */
          bi = xor(delta, prp.decrypt(xor(delta, datacache.slice(i, i + 4))));
          checksum = xor(checksum, bi);
          output = output.concat(bi);
          delta = times2(delta);
        }
        datacache = datacache.slice(i);
        return output;
      },
      finalize: function () {
        /* Chop out and decrypt the final block */
        bl = sjcl.bitArray.bitLength(datacache) - tlen;
        pad = prp.encrypt(xor(delta, [0, 0, 0, bl]));
        bi = xor(pad, w.clamp(datacache, bl).concat([0, 0, 0]));

        /* Checksum the final block, and finalize the checksum */
        checksum = xor(checksum, bi);
        checksum = prp.encrypt(xor(checksum, xor(delta, times2(delta))));

        /* MAC the header */
        if (adata.length) {
          checksum = xor(
            checksum,
            premac ? adata : sjcl.mode.ocb2.pmac(prp, adata)
          );
        }

        if (!w.equal(w.clamp(checksum, tlen), w.bitSlice(datacache, bl))) {
          throw new sjcl.exception.corrupt("ocb: tag doesn't match");
        }

        return w.clamp(bi, bl);
      }
    };
  }
};
/** @fileOverview Password-based key-derivation function, version 2.0.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** Password-Based Key-Derivation Function, version 2.0.
 *
 * Generate keys from passwords using PBKDF2-HMAC-SHA256.
 *
 * This is the method specified by RSA's PKCS #5 standard.
 *
 * @param {bitArray|String} password  The password.
 * @param {bitArray|String} salt The salt.  Should have lots of entropy.
 * @param {Number} [count=1000] The number of iterations.  Higher numbers make the function slower but more secure.
 * @param {Number} [length] The length of the derived key.  Defaults to the
                            output size of the hash function.
 * @param {Object} [Prff=sjcl.misc.hmac] The pseudorandom function family.
 * @return {bitArray} the derived key.
 */
sjcl.misc.pbkdf2 = function (password, salt, count, length, Prff) {
  count = count || 10000;

  if (length < 0 || count < 0) {
    throw new sjcl.exception.invalid("invalid params to pbkdf2");
  }

  if (typeof password === "string") {
    password = sjcl.codec.utf8String.toBits(password);
  }

  if (typeof salt === "string") {
    salt = sjcl.codec.utf8String.toBits(salt);
  }

  Prff = Prff || sjcl.misc.hmac;

  var prf = new Prff(password),
    u,
    ui,
    i,
    j,
    k,
    out = [],
    b = sjcl.bitArray;

  for (k = 1; 32 * out.length < (length || 1); k++) {
    u = ui = prf.encrypt(b.concat(salt, [k]));

    for (i = 1; i < count; i++) {
      ui = prf.encrypt(ui);
      for (j = 0; j < ui.length; j++) {
        u[j] ^= ui[j];
      }
    }

    out = out.concat(u);
  }

  if (length) {
    out = b.clamp(out, length);
  }

  return out;
};
/** @fileOverview Random number generator.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Michael Brooks
 * @author Steve Thomas
 */

/**
 * @class Random number generator
 * @description
 * <b>Use sjcl.random as a singleton for this class!</b>
 * <p>
 * This random number generator is a derivative of Ferguson and Schneier's
 * generator Fortuna.  It collects entropy from various events into several
 * pools, implemented by streaming SHA-256 instances.  It differs from
 * ordinary Fortuna in a few ways, though.
 * </p>
 *
 * <p>
 * Most importantly, it has an entropy estimator.  This is present because
 * there is a strong conflict here between making the generator available
 * as soon as possible, and making sure that it doesn't "run on empty".
 * In Fortuna, there is a saved state file, and the system is likely to have
 * time to warm up.
 * </p>
 *
 * <p>
 * Second, because users are unlikely to stay on the page for very long,
 * and to speed startup time, the number of pools increases logarithmically:
 * a new pool is created when the previous one is actually used for a reseed.
 * This gives the same asymptotic guarantees as Fortuna, but gives more
 * entropy to early reseeds.
 * </p>
 *
 * <p>
 * The entire mechanism here feels pretty klunky.  Furthermore, there are
 * several improvements that should be made, including support for
 * dedicated cryptographic functions that may be present in some browsers;
 * state files in local storage; cookies containing randomness; etc.  So
 * look for improvements in future versions.
 * </p>
 * @constructor
 */
sjcl.prng = function (defaultParanoia) {
  /* private */
  this._pools = [new sjcl.hash.sha256()];
  this._poolEntropy = [0];
  this._reseedCount = 0;
  this._robins = {};
  this._eventId = 0;

  this._collectorIds = {};
  this._collectorIdNext = 0;

  this._strength = 0;
  this._poolStrength = 0;
  this._nextReseed = 0;
  this._key = [0, 0, 0, 0, 0, 0, 0, 0];
  this._counter = [0, 0, 0, 0];
  this._cipher = undefined;
  this._defaultParanoia = defaultParanoia;

  /* event listener stuff */
  this._collectorsStarted = false;
  this._callbacks = { progress: {}, seeded: {} };
  this._callbackI = 0;

  /* constants */
  this._NOT_READY = 0;
  this._READY = 1;
  this._REQUIRES_RESEED = 2;

  this._MAX_WORDS_PER_BURST = 65536;
  this._PARANOIA_LEVELS = [0, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024];
  this._MILLISECONDS_PER_RESEED = 30000;
  this._BITS_PER_RESEED = 80;
};

sjcl.prng.prototype = {
  /** Generate several random words, and return them in an array.
   * A word consists of 32 bits (4 bytes)
   * @param {Number} nwords The number of words to generate.
   */
  randomWords: function (nwords, paranoia) {
    var out = [],
      i,
      readiness = this.isReady(paranoia),
      g;

    if (readiness === this._NOT_READY) {
      throw new sjcl.exception.notReady("generator isn't seeded");
    } else if (readiness & this._REQUIRES_RESEED) {
      this._reseedFromPools(!(readiness & this._READY));
    }

    for (i = 0; i < nwords; i += 4) {
      if ((i + 1) % this._MAX_WORDS_PER_BURST === 0) {
        this._gate();
      }

      g = this._gen4words();
      out.push(g[0], g[1], g[2], g[3]);
    }
    this._gate();

    return out.slice(0, nwords);
  },

  setDefaultParanoia: function (paranoia, allowZeroParanoia) {
    if (
      paranoia === 0 &&
      allowZeroParanoia !==
        "Setting paranoia=0 will ruin your security; use it only for testing"
    ) {
      throw new sjcl.exception.invalid(
        "Setting paranoia=0 will ruin your security; use it only for testing"
      );
    }

    this._defaultParanoia = paranoia;
  },

  /**
   * Add entropy to the pools.
   * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
   * @param {Number} estimatedEntropy The estimated entropy of data, in bits
   * @param {String} source The source of the entropy, eg "mouse"
   */
  addEntropy: function (data, estimatedEntropy, source) {
    source = source || "user";

    var id,
      i,
      tmp,
      t = new Date().valueOf(),
      robin = this._robins[source],
      oldReady = this.isReady(),
      err = 0,
      objName;

    id = this._collectorIds[source];
    if (id === undefined) {
      id = this._collectorIds[source] = this._collectorIdNext++;
    }

    if (robin === undefined) {
      robin = this._robins[source] = 0;
    }
    this._robins[source] = (this._robins[source] + 1) % this._pools.length;

    switch (typeof data) {
      case "number":
        if (estimatedEntropy === undefined) {
          estimatedEntropy = 1;
        }
        this._pools[robin].update([
          id,
          this._eventId++,
          1,
          estimatedEntropy,
          t,
          1,
          data | 0
        ]);
        break;

      case "object":
        objName = Object.prototype.toString.call(data);
        if (objName === "[object Uint32Array]") {
          tmp = [];
          for (i = 0; i < data.length; i++) {
            tmp.push(data[i]);
          }
          data = tmp;
        } else {
          if (objName !== "[object Array]") {
            err = 1;
          }
          for (i = 0; i < data.length && !err; i++) {
            if (typeof data[i] !== "number") {
              err = 1;
            }
          }
        }
        if (!err) {
          if (estimatedEntropy === undefined) {
            /* horrible entropy estimator */
            estimatedEntropy = 0;
            for (i = 0; i < data.length; i++) {
              tmp = data[i];
              while (tmp > 0) {
                estimatedEntropy++;
                tmp = tmp >>> 1;
              }
            }
          }
          this._pools[robin].update(
            [id, this._eventId++, 2, estimatedEntropy, t, data.length].concat(
              data
            )
          );
        }
        break;

      case "string":
        if (estimatedEntropy === undefined) {
          /* English text has just over 1 bit per character of entropy.
           * But this might be HTML or something, and have far less
           * entropy than English...  Oh well, let's just say one bit.
           */
          estimatedEntropy = data.length;
        }
        this._pools[robin].update([
          id,
          this._eventId++,
          3,
          estimatedEntropy,
          t,
          data.length
        ]);
        this._pools[robin].update(data);
        break;

      default:
        err = 1;
    }
    if (err) {
      throw new sjcl.exception.bug(
        "random: addEntropy only supports number, array of numbers or string"
      );
    }

    /* record the new strength */
    this._poolEntropy[robin] += estimatedEntropy;
    this._poolStrength += estimatedEntropy;

    /* fire off events */
    if (oldReady === this._NOT_READY) {
      if (this.isReady() !== this._NOT_READY) {
        this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
      }
      this._fireEvent("progress", this.getProgress());
    }
  },

  /** Is the generator ready? */
  isReady: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[
      paranoia !== undefined ? paranoia : this._defaultParanoia
    ];

    if (this._strength && this._strength >= entropyRequired) {
      return this._poolEntropy[0] > this._BITS_PER_RESEED &&
        new Date().valueOf() > this._nextReseed
        ? this._REQUIRES_RESEED | this._READY
        : this._READY;
    } else {
      return this._poolStrength >= entropyRequired
        ? this._REQUIRES_RESEED | this._NOT_READY
        : this._NOT_READY;
    }
  },

  /** Get the generator's progress toward readiness, as a fraction */
  getProgress: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[
      paranoia ? paranoia : this._defaultParanoia
    ];

    if (this._strength >= entropyRequired) {
      return 1.0;
    } else {
      return this._poolStrength > entropyRequired
        ? 1.0
        : this._poolStrength / entropyRequired;
    }
  },

  /** start the built-in entropy collectors */
  startCollectors: function () {
    if (this._collectorsStarted) {
      return;
    }

    this._eventListener = {
      loadTimeCollector: this._bind(this._loadTimeCollector),
      mouseCollector: this._bind(this._mouseCollector),
      keyboardCollector: this._bind(this._keyboardCollector),
      accelerometerCollector: this._bind(this._accelerometerCollector),
      touchCollector: this._bind(this._touchCollector)
    };

    if (window.addEventListener) {
      window.addEventListener(
        "load",
        this._eventListener.loadTimeCollector,
        false
      );
      window.addEventListener(
        "mousemove",
        this._eventListener.mouseCollector,
        false
      );
      window.addEventListener(
        "keypress",
        this._eventListener.keyboardCollector,
        false
      );
      window.addEventListener(
        "devicemotion",
        this._eventListener.accelerometerCollector,
        false
      );
      window.addEventListener(
        "touchmove",
        this._eventListener.touchCollector,
        false
      );
    } else if (document.attachEvent) {
      document.attachEvent("onload", this._eventListener.loadTimeCollector);
      document.attachEvent("onmousemove", this._eventListener.mouseCollector);
      document.attachEvent("keypress", this._eventListener.keyboardCollector);
    } else {
      throw new sjcl.exception.bug("can't attach event");
    }

    this._collectorsStarted = true;
  },

  /** stop the built-in entropy collectors */
  stopCollectors: function () {
    if (!this._collectorsStarted) {
      return;
    }

    if (window.removeEventListener) {
      window.removeEventListener(
        "load",
        this._eventListener.loadTimeCollector,
        false
      );
      window.removeEventListener(
        "mousemove",
        this._eventListener.mouseCollector,
        false
      );
      window.removeEventListener(
        "keypress",
        this._eventListener.keyboardCollector,
        false
      );
      window.removeEventListener(
        "devicemotion",
        this._eventListener.accelerometerCollector,
        false
      );
      window.removeEventListener(
        "touchmove",
        this._eventListener.touchCollector,
        false
      );
    } else if (document.detachEvent) {
      document.detachEvent("onload", this._eventListener.loadTimeCollector);
      document.detachEvent("onmousemove", this._eventListener.mouseCollector);
      document.detachEvent("keypress", this._eventListener.keyboardCollector);
    }

    this._collectorsStarted = false;
  },

  /* use a cookie to store entropy.
  useCookie: function (all_cookies) {
      throw new sjcl.exception.bug("random: useCookie is unimplemented");
  },*/

  /** add an event listener for progress or seeded-ness. */
  addEventListener: function (name, callback) {
    this._callbacks[name][this._callbackI++] = callback;
  },

  /** remove an event listener for progress or seeded-ness */
  removeEventListener: function (name, cb) {
    var i,
      j,
      cbs = this._callbacks[name],
      jsTemp = [];

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */

    for (j in cbs) {
      if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
        jsTemp.push(j);
      }
    }

    for (i = 0; i < jsTemp.length; i++) {
      j = jsTemp[i];
      delete cbs[j];
    }
  },

  _bind: function (func) {
    var that = this;
    return function () {
      func.apply(that, arguments);
    };
  },

  /** Generate 4 random words, no reseed, no gate.
   * @private
   */
  _gen4words: function () {
    for (var i = 0; i < 4; i++) {
      this._counter[i] = (this._counter[i] + 1) | 0;
      if (this._counter[i]) {
        break;
      }
    }
    return this._cipher.encrypt(this._counter);
  },

  /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
   * @private
   */
  _gate: function () {
    this._key = this._gen4words().concat(this._gen4words());
    this._cipher = new sjcl.cipher.aes(this._key);
  },

  /** Reseed the generator with the given words
   * @private
   */
  _reseed: function (seedWords) {
    this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
    this._cipher = new sjcl.cipher.aes(this._key);
    for (var i = 0; i < 4; i++) {
      this._counter[i] = (this._counter[i] + 1) | 0;
      if (this._counter[i]) {
        break;
      }
    }
  },

  /** reseed the data from the entropy pools
   * @param full If set, use all the entropy pools in the reseed.
   */
  _reseedFromPools: function (full) {
    var reseedData = [],
      strength = 0,
      i;

    this._nextReseed = reseedData[0] =
      new Date().valueOf() + this._MILLISECONDS_PER_RESEED;

    for (i = 0; i < 16; i++) {
      /* On some browsers, this is cryptographically random.  So we might
       * as well toss it in the pot and stir...
       */
      reseedData.push((Math.random() * 0x100000000) | 0);
    }

    for (i = 0; i < this._pools.length; i++) {
      reseedData = reseedData.concat(this._pools[i].finalize());
      strength += this._poolEntropy[i];
      this._poolEntropy[i] = 0;

      if (!full && this._reseedCount & (1 << i)) {
        break;
      }
    }

    /* if we used the last pool, push a new one onto the stack */
    if (this._reseedCount >= 1 << this._pools.length) {
      this._pools.push(new sjcl.hash.sha256());
      this._poolEntropy.push(0);
    }

    /* how strong was this reseed? */
    this._poolStrength -= strength;
    if (strength > this._strength) {
      this._strength = strength;
    }

    this._reseedCount++;
    this._reseed(reseedData);
  },

  _keyboardCollector: function () {
    this._addCurrentTimeToEntropy(1);
  },

  _mouseCollector: function (ev) {
    var x, y;

    try {
      x = ev.x || ev.clientX || ev.offsetX || 0;
      y = ev.y || ev.clientY || ev.offsetY || 0;
    } catch (err) {
      // Event originated from a secure element. No mouse position available.
      x = 0;
      y = 0;
    }

    if (x != 0 && y != 0) {
      this.addEntropy([x, y], 2, "mouse");
    }

    this._addCurrentTimeToEntropy(0);
  },

  _touchCollector: function (ev) {
    var touch = ev.touches[0] || ev.changedTouches[0];
    var x = touch.pageX || touch.clientX,
      y = touch.pageY || touch.clientY;

    this.addEntropy([x, y], 1, "touch");

    this._addCurrentTimeToEntropy(0);
  },

  _loadTimeCollector: function () {
    this._addCurrentTimeToEntropy(2);
  },

  _addCurrentTimeToEntropy: function (estimatedEntropy) {
    if (
      typeof window !== "undefined" &&
      window.performance &&
      typeof window.performance.now === "function"
    ) {
      //how much entropy do we want to add here?
      this.addEntropy(window.performance.now(), estimatedEntropy, "loadtime");
    } else {
      this.addEntropy(new Date().valueOf(), estimatedEntropy, "loadtime");
    }
  },
  _accelerometerCollector: function (ev) {
    var ac =
      ev.accelerationIncludingGravity.x ||
      ev.accelerationIncludingGravity.y ||
      ev.accelerationIncludingGravity.z;
    if (window.orientation) {
      var or = window.orientation;
      if (typeof or === "number") {
        this.addEntropy(or, 1, "accelerometer");
      }
    }
    if (ac) {
      this.addEntropy(ac, 2, "accelerometer");
    }
    this._addCurrentTimeToEntropy(0);
  },

  _fireEvent: function (name, arg) {
    var j,
      cbs = sjcl.random._callbacks[name],
      cbsTemp = [];
    /* TODO: there is a race condition between removing collectors and firing them */

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */

    for (j in cbs) {
      if (cbs.hasOwnProperty(j)) {
        cbsTemp.push(cbs[j]);
      }
    }

    for (j = 0; j < cbsTemp.length; j++) {
      cbsTemp[j](arg);
    }
  }
};

(function () {
  // function for getting nodejs crypto module. catches and ignores errors.
  function getCryptoModule() {
    try {
      return require("crypto");
    } catch (e) {
      return null;
    }
  }

  try {
    var buf, crypt, ab;

    // get cryptographically strong entropy depending on runtime environment
    if (
      typeof module !== "undefined" &&
      module.exports &&
      (crypt = getCryptoModule()) &&
      crypt.randomBytes
    ) {
      buf = crypt.randomBytes(1024 / 8);
      buf = new Uint32Array(new Uint8Array(buf).buffer);
      sjcl.random.addEntropy(buf, 1024, "crypto.randomBytes");
    } else if (
      typeof window !== "undefined" &&
      typeof Uint32Array !== "undefined"
    ) {
      ab = new Uint32Array(32);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(ab);
      } else if (window.msCrypto && window.msCrypto.getRandomValues) {
        window.msCrypto.getRandomValues(ab);
      } else {
        return;
      }

      // get cryptographically strong entropy in Webkit
      sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");
    } else {
      // no getRandomValues :-(
    }
  } catch (e) {
    if (typeof window !== "undefined" && window.console) {
      console.log("There was an error collecting entropy from the browser:");
      console.log(e);
      //we do not want the library to fail due to randomness not being maintained.
    }
  }
})();
/** @fileOverview Javascript RIPEMD-160 implementation.
 *
 * @author Artem S Vybornov <vybornov@gmail.com>
 */
(function () {
  /**
   * Context for a RIPEMD-160 operation in progress.
   * @constructor
   */
  sjcl.hash.ripemd160 = function (hash) {
    if (hash) {
      this._h = hash._h.slice(0);
      this._buffer = hash._buffer.slice(0);
      this._length = hash._length;
    } else {
      this.reset();
    }
  };

  /**
   * Hash a string or an array of words.
   * @static
   * @param {bitArray|String} data the data to hash.
   * @return {bitArray} The hash value, an array of 5 big-endian words.
   */
  sjcl.hash.ripemd160.hash = function (data) {
    return new sjcl.hash.ripemd160().update(data).finalize();
  };

  sjcl.hash.ripemd160.prototype = {
    /**
     * Reset the hash state.
     * @return this
     */
    reset: function () {
      this._h = _h0.slice(0);
      this._buffer = [];
      this._length = 0;
      return this;
    },

    /**
     * Reset the hash state.
     * @param {bitArray|String} data the data to hash.
     * @return this
     */
    update: function (data) {
      if (typeof data === "string") data = sjcl.codec.utf8String.toBits(data);

      var i,
        b = (this._buffer = sjcl.bitArray.concat(this._buffer, data)),
        ol = this._length,
        nl = (this._length = ol + sjcl.bitArray.bitLength(data));
      if (nl > 9007199254740991) {
        throw new sjcl.exception.invalid("Cannot hash more than 2^53 - 1 bits");
      }
      for (i = 512 + ol - ((512 + ol) & 511); i <= nl; i += 512) {
        var words = b.splice(0, 16);
        for (var w = 0; w < 16; ++w) words[w] = _cvt(words[w]);

        _block.call(this, words);
      }

      return this;
    },

    /**
     * Complete hashing and output the hash value.
     * @return {bitArray} The hash value, an array of 5 big-endian words.
     */
    finalize: function () {
      var b = sjcl.bitArray.concat(this._buffer, [sjcl.bitArray.partial(1, 1)]),
        l = (this._length + 1) % 512,
        z = (l > 448 ? 512 : 448) - (l % 448),
        zp = z % 32;

      if (zp > 0) b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(zp, 0)]);
      for (; z >= 32; z -= 32) b.push(0);

      b.push(_cvt(this._length | 0));
      b.push(_cvt(Math.floor(this._length / 0x100000000)));

      while (b.length) {
        var words = b.splice(0, 16);
        for (var w = 0; w < 16; ++w) words[w] = _cvt(words[w]);

        _block.call(this, words);
      }

      var h = this._h;
      this.reset();

      for (var w = 0; w < 5; ++w) h[w] = _cvt(h[w]);

      return h;
    }
  };

  var _h0 = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

  var _k1 = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  var _k2 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  for (var i = 4; i >= 0; --i) {
    for (var j = 1; j < 16; ++j) {
      _k1.splice(i, 0, _k1[i]);
      _k2.splice(i, 0, _k2[i]);
    }
  }

  var _r1 = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8,
    3,
    10,
    14,
    4,
    9,
    15,
    8,
    1,
    2,
    7,
    0,
    6,
    13,
    11,
    5,
    12,
    1,
    9,
    11,
    10,
    0,
    8,
    12,
    4,
    13,
    3,
    7,
    15,
    14,
    5,
    6,
    2,
    4,
    0,
    5,
    9,
    7,
    12,
    2,
    10,
    14,
    1,
    3,
    8,
    11,
    6,
    15,
    13
  ];
  var _r2 = [
    5,
    14,
    7,
    0,
    9,
    2,
    11,
    4,
    13,
    6,
    15,
    8,
    1,
    10,
    3,
    12,
    6,
    11,
    3,
    7,
    0,
    13,
    5,
    10,
    14,
    15,
    8,
    12,
    4,
    9,
    1,
    2,
    15,
    5,
    1,
    3,
    7,
    14,
    6,
    9,
    11,
    8,
    12,
    2,
    10,
    0,
    4,
    13,
    8,
    6,
    4,
    1,
    3,
    11,
    15,
    0,
    5,
    12,
    2,
    13,
    9,
    7,
    10,
    14,
    12,
    15,
    10,
    4,
    1,
    5,
    8,
    7,
    6,
    2,
    13,
    14,
    0,
    3,
    9,
    11
  ];

  var _s1 = [
    11,
    14,
    15,
    12,
    5,
    8,
    7,
    9,
    11,
    13,
    14,
    15,
    6,
    7,
    9,
    8,
    7,
    6,
    8,
    13,
    11,
    9,
    7,
    15,
    7,
    12,
    15,
    9,
    11,
    7,
    13,
    12,
    11,
    13,
    6,
    7,
    14,
    9,
    13,
    15,
    14,
    8,
    13,
    6,
    5,
    12,
    7,
    5,
    11,
    12,
    14,
    15,
    14,
    15,
    9,
    8,
    9,
    14,
    5,
    6,
    8,
    6,
    5,
    12,
    9,
    15,
    5,
    11,
    6,
    8,
    13,
    12,
    5,
    12,
    13,
    14,
    11,
    8,
    5,
    6
  ];
  var _s2 = [
    8,
    9,
    9,
    11,
    13,
    15,
    15,
    5,
    7,
    7,
    8,
    11,
    14,
    14,
    12,
    6,
    9,
    13,
    15,
    7,
    12,
    8,
    9,
    11,
    7,
    7,
    12,
    7,
    6,
    15,
    13,
    11,
    9,
    7,
    15,
    11,
    8,
    6,
    6,
    14,
    12,
    13,
    5,
    14,
    13,
    13,
    7,
    5,
    15,
    5,
    8,
    11,
    14,
    14,
    6,
    14,
    6,
    9,
    12,
    9,
    12,
    5,
    15,
    8,
    8,
    5,
    12,
    9,
    12,
    5,
    14,
    6,
    8,
    13,
    6,
    5,
    15,
    13,
    11,
    11
  ];

  function _f0(x, y, z) {
    return x ^ y ^ z;
  }

  function _f1(x, y, z) {
    return (x & y) | (~x & z);
  }

  function _f2(x, y, z) {
    return (x | ~y) ^ z;
  }

  function _f3(x, y, z) {
    return (x & z) | (y & ~z);
  }

  function _f4(x, y, z) {
    return x ^ (y | ~z);
  }

  function _rol(n, l) {
    return (n << l) | (n >>> (32 - l));
  }

  function _cvt(n) {
    return (
      ((n & (0xff << 0)) << 24) |
      ((n & (0xff << 8)) << 8) |
      ((n & (0xff << 16)) >>> 8) |
      ((n & (0xff << 24)) >>> 24)
    );
  }

  function _block(X) {
    var A1 = this._h[0],
      B1 = this._h[1],
      C1 = this._h[2],
      D1 = this._h[3],
      E1 = this._h[4],
      A2 = this._h[0],
      B2 = this._h[1],
      C2 = this._h[2],
      D2 = this._h[3],
      E2 = this._h[4];

    var j = 0,
      T;

    for (; j < 16; ++j) {
      T = _rol(A1 + _f0(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f4(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    for (; j < 32; ++j) {
      T = _rol(A1 + _f1(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f3(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    for (; j < 48; ++j) {
      T = _rol(A1 + _f2(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f2(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    for (; j < 64; ++j) {
      T = _rol(A1 + _f3(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f1(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    for (; j < 80; ++j) {
      T = _rol(A1 + _f4(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f0(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }

    T = this._h[1] + C1 + D2;
    this._h[1] = this._h[2] + D1 + E2;
    this._h[2] = this._h[3] + E1 + A2;
    this._h[3] = this._h[4] + A1 + B2;
    this._h[4] = this._h[0] + B1 + C2;
    this._h[0] = T;
  }
})();
/** @fileOverview Javascript SHA-256 implementation.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * Special thanks to Aldo Cortesi for pointing out several bugs in
 * this code.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Context for a SHA-256 operation in progress.
 * @constructor
 */
sjcl.hash.sha256 = function (hash) {
  if (!this._key[0]) {
    this._precompute();
  }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 16 big-endian words.
 */
sjcl.hash.sha256.hash = function (data) {
  return new sjcl.hash.sha256().update(data).finalize();
};

sjcl.hash.sha256.prototype = {
  /**
   * The hash's block size, in bits.
   * @constant
   */
  blockSize: 512,

  /**
   * Reset the hash state.
   * @return this
   */
  reset: function () {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },

  export: function () {
    return JSON.stringify([this._h, this._buffer, this._length]);
  },

  import: function (data) {
    var _data = JSON.parse(data);
    this._h = _data[0];
    this._buffer = _data[1];
    this._length = _data[2];
  },

  /**
   * Input several words to the hash.
   * @param {bitArray|String} data the data to hash.
   * @return this
   */
  update: function (data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i,
      b = (this._buffer = sjcl.bitArray.concat(this._buffer, data)),
      ol = this._length,
      nl = (this._length = ol + sjcl.bitArray.bitLength(data));
    if (nl > 9007199254740991) {
      throw new sjcl.exception.invalid("Cannot hash more than 2^53 - 1 bits");
    }

    // (Yoni:) Every 512 characters this._h and this._length gets updated...
    if (typeof Uint32Array !== "undefined") {
      var c = new Uint32Array(b);
      var j = 0;
      for (i = 512 + ol - ((512 + ol) & 511); i <= nl; i += 512) {
        this._block(c.subarray(16 * j, 16 * (j + 1)));
        j += 1;
      }
      b.splice(0, 16 * j);
    } else {
      for (i = 512 + ol - ((512 + ol) & 511); i <= nl; i += 512) {
        this._block(b.splice(0, 16));
      }
    }
    return this;
  },

  /**
   * Complete hashing and output the hash value.
   * @return {bitArray} The hash value, an array of 8 big-endian words.
   */
  finalize: function () {
    var i,
      b = this._buffer,
      h = this._h;

    // Round out and push the buffer
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);

    // Round out the buffer to a multiple of 16 words, less the 2 length words.
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }

    // append the length
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);

    while (b.length) {
      this._block(b.splice(0, 16));
    }

    this.reset();
    return h;
  },

  /**
   * The SHA-256 initialization vector, to be precomputed.
   * @private
   */
  _init: [],
  /*
  _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
  */

  /**
   * The SHA-256 hash key, to be precomputed.
   * @private
   */
  _key: [],
  /*
  _key:
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
  */

  /**
   * Function to precompute _init and _key.
   * @private
   */
  _precompute: function () {
    var i = 0,
      prime = 2,
      factor,
      isPrime;

    function frac(x) {
      return ((x - Math.floor(x)) * 0x100000000) | 0;
    }

    for (; i < 64; prime++) {
      isPrime = true;
      for (factor = 2; factor * factor <= prime; factor++) {
        if (prime % factor === 0) {
          isPrime = false;
          break;
        }
      }
      if (isPrime) {
        if (i < 8) {
          this._init[i] = frac(Math.pow(prime, 1 / 2));
        }
        this._key[i] = frac(Math.pow(prime, 1 / 3));
        i++;
      }
    }
  },

  /**
   * Perform one cycle of SHA-256.
   * @param {Uint32Array|bitArray} w one block of words.
   * @private
   */
  _block: function (w) {
    var i,
      tmp,
      a,
      b,
      h = this._h,
      k = this._key,
      h0 = h[0],
      h1 = h[1],
      h2 = h[2],
      h3 = h[3],
      h4 = h[4],
      h5 = h[5],
      h6 = h[6],
      h7 = h[7];

    /* Rationale for placement of |0 :
     * If a value can overflow is original 32 bits by a factor of more than a few
     * million (2^23 ish), there is a possibility that it might overflow the
     * 53-bit mantissa and lose precision.
     *
     * To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
     * propagates around the loop, and on the hash state h[].  I don't believe
     * that the clamps on h4 and on h0 are strictly necessary, but it's close
     * (for h4 anyway), and better safe than sorry.
     *
     * The clamps on h[] are necessary for the output to be correct even in the
     * common case and for short inputs.
     */
    for (i = 0; i < 64; i++) {
      // load up the input word for this round
      if (i < 16) {
        tmp = w[i];
      } else {
        a = w[(i + 1) & 15];
        b = w[(i + 14) & 15];
        tmp = w[i & 15] =
          (((a >>> 7) ^ (a >>> 18) ^ (a >>> 3) ^ (a << 25) ^ (a << 14)) +
            ((b >>> 17) ^ (b >>> 19) ^ (b >>> 10) ^ (b << 15) ^ (b << 13)) +
            w[i & 15] +
            w[(i + 9) & 15]) |
          0;
      }

      tmp =
        tmp +
        h7 +
        ((h4 >>> 6) ^
          (h4 >>> 11) ^
          (h4 >>> 25) ^
          (h4 << 26) ^
          (h4 << 21) ^
          (h4 << 7)) +
        (h6 ^ (h4 & (h5 ^ h6))) +
        k[i]; // | 0;

      // shift register
      h7 = h6;
      h6 = h5;
      h5 = h4;
      h4 = (h3 + tmp) | 0;
      h3 = h2;
      h2 = h1;
      h1 = h0;

      h0 =
        (tmp +
          ((h1 & h2) ^ (h3 & (h1 ^ h2))) +
          ((h1 >>> 2) ^
            (h1 >>> 13) ^
            (h1 >>> 22) ^
            (h1 << 30) ^
            (h1 << 19) ^
            (h1 << 10))) |
        0;
    }

    h[0] = (h[0] + h0) | 0;
    h[1] = (h[1] + h1) | 0;
    h[2] = (h[2] + h2) | 0;
    h[3] = (h[3] + h3) | 0;
    h[4] = (h[4] + h4) | 0;
    h[5] = (h[5] + h5) | 0;
    h[6] = (h[6] + h6) | 0;
    h[7] = (h[7] + h7) | 0;

    //console.log("_block_h", JSON.stringify([h, this._h]));
  }
};

/** @fileOverview Javascript SRP implementation.
 *
 * This file contains a partial implementation of the SRP (Secure Remote
 * Password) password-authenticated key exchange protocol. Given a user
 * identity, salt, and SRP group, it generates the SRP verifier that may
 * be sent to a remote server to establish and SRP account.
 *
 * For more information, see http://srp.stanford.edu/.
 *
 * @author Quinn Slack
 */

/**
 * Compute the SRP verifier from the username, password, salt, and group.
 * @namespace
 */
sjcl.keyexchange.srp = {
  /**
   * Calculates SRP v, the verifier.
   *   v = g^x mod N [RFC 5054]
   * @param {String} I The username.
   * @param {String} P The password.
   * @param {Object} s A bitArray of the salt.
   * @param {Object} group The SRP group. Use sjcl.keyexchange.srp.knownGroup
                           to obtain this object.
   * @return {Object} A bitArray of SRP v.
   */
  makeVerifier: function (I, P, s, group) {
    var x;
    x = sjcl.keyexchange.srp.makeX(I, P, s);
    x = sjcl.bn.fromBits(x);
    return group.g.powermod(x, group.N);
  },

  /**
   * Calculates SRP x.
   *   x = SHA1(<salt> | SHA(<username> | ":" | <raw password>)) [RFC 2945]
   * @param {String} I The username.
   * @param {String} P The password.
   * @param {Object} s A bitArray of the salt.
   * @return {Object} A bitArray of SRP x.
   */
  makeX: function (I, P, s) {
    var inner = sjcl.hash.sha1.hash(I + ":" + P);
    return sjcl.hash.sha1.hash(sjcl.bitArray.concat(s, inner));
  },

  /**
   * Returns the known SRP group with the given size (in bits).
   * @param {String} i The size of the known SRP group.
   * @return {Object} An object with "N" and "g" properties.
   */
  knownGroup: function (i) {
    if (typeof i !== "string") {
      i = i.toString();
    }
    if (!sjcl.keyexchange.srp._didInitKnownGroups) {
      sjcl.keyexchange.srp._initKnownGroups();
    }
    return sjcl.keyexchange.srp._knownGroups[i];
  },

  /**
   * Initializes bignum objects for known group parameters.
   * @private
   */
  _didInitKnownGroups: false,
  _initKnownGroups: function () {
    var i, size, group;
    for (i = 0; i < sjcl.keyexchange.srp._knownGroupSizes.length; i++) {
      size = sjcl.keyexchange.srp._knownGroupSizes[i].toString();
      group = sjcl.keyexchange.srp._knownGroups[size];
      group.N = new sjcl.bn(group.N);
      group.g = new sjcl.bn(group.g);
    }
    sjcl.keyexchange.srp._didInitKnownGroups = true;
  },

  _knownGroupSizes: [1024, 1536, 2048, 3072, 4096, 6144, 8192],
  _knownGroups: {
    1024: {
      N:
        "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
        "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
        "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
        "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
        "FD5138FE8376435B9FC61D2FC0EB06E3",
      g: 2
    },

    1536: {
      N:
        "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961" +
        "4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843" +
        "80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B" +
        "E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5" +
        "6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A" +
        "F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E" +
        "8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
      g: 2
    },

    2048: {
      N:
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
        "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
        "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
        "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
        "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
        "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
        "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
        "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
        "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
        "9E4AFF73",
      g: 2
    },

    3072: {
      N:
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
        "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
        "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
        "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
        "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
        "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
        "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
      g: 5
    },

    4096: {
      N:
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
        "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
        "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
        "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
        "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
        "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
        "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26" +
        "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB" +
        "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
        "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
        "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
        "FFFFFFFFFFFFFFFF",
      g: 5
    },

    6144: {
      N:
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
        "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
        "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
        "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
        "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
        "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
        "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26" +
        "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB" +
        "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
        "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
        "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492" +
        "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406" +
        "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918" +
        "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151" +
        "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03" +
        "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F" +
        "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA" +
        "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B" +
        "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632" +
        "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E" +
        "6DCC4024FFFFFFFFFFFFFFFF",
      g: 5
    },

    8192: {
      N:
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
        "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
        "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
        "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
        "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
        "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
        "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26" +
        "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB" +
        "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
        "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
        "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492" +
        "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406" +
        "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918" +
        "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151" +
        "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03" +
        "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F" +
        "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA" +
        "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B" +
        "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632" +
        "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E" +
        "6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA" +
        "3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C" +
        "5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9" +
        "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886" +
        "2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6" +
        "6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5" +
        "0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268" +
        "359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6" +
        "FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71" +
        "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
      g: 19
    }
  }
};

/** an instance for the prng.
 * @see sjcl.prng
 */
sjcl.random = new sjcl.prng(6);

module.exports = sjcl;
