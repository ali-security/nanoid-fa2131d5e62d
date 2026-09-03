let { test } = require('uvu')
let { is, ok, equal, match, not, throws } = require('uvu/assert')

let browser = require('../index.browser.js')
let node = require('../index.js')

test.before(() => {
  global.crypto = {
    getRandomValues(array) {
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256)
      }
      return array
    }
  }
})

test.after(() => {
  delete global.crypto
})

for (let type of ['node', 'browser']) {
  let { nanoid, customAlphabet, customRandom, random, urlAlphabet } =
    type === 'node' ? node : browser

  test(`${type} / nanoid / generates URL-friendly IDs`, () => {
    for (let i = 0; i < 100; i++) {
      let id = nanoid()
      is(id.length, 21)
      is(typeof id, 'string')
      for (let char of id) {
        match(urlAlphabet, new RegExp(char, "g"))
      }
    }
  })

  test(`${type} / nanoid / avoids pool pollution, infinite loop`, () => {
    nanoid(2.1)
    let second = nanoid()
    let third = nanoid()
    not.equal(second, third)
  })

  test(`${type} / nanoid / changes ID length`, () => {
    is(nanoid(10).length, 10)
  })

  test(`${type} / nanoid / accepts string`, () => {
    is(nanoid('10').length, 10)
  })

  test(`${type} / nanoid / has no collisions`, () => {
    let used = {}
    for (let i = 0; i < 50 * 1000; i++) {
      let id = nanoid()
      is(used[id], undefined)
      used[id] = true
    }
  })

  test(`${type} / nanoid / has flat distribution`, () => {
    let COUNT = 100 * 1000
    let LENGTH = nanoid().length

    let chars = {}
    for (let i = 0; i < COUNT; i++) {
      let id = nanoid()
      for (let char of id) {
        if (!chars[char]) chars[char] = 0
        chars[char] += 1
      }
    }

    is(Object.keys(chars).length, urlAlphabet.length)

    let max = 0
    let min = Number.MAX_SAFE_INTEGER
    for (let k in chars) {
      let distribution = (chars[k] * urlAlphabet.length) / (COUNT * LENGTH)
      if (distribution > max) max = distribution
      if (distribution < min) min = distribution
    }
    ok(max - min <= 0.05)
  })

  test(`${type} / customAlphabet / has options`, () => {
    let nanoidA = customAlphabet('a', 5)
    is(nanoidA(), 'aaaaa')
  })

  test(`${type} / customAlphabet / has flat distribution`, () => {
    let COUNT = 50 * 1000
    let LENGTH = 30
    let ALPHABET = 'abcdefghijklmnopqrstuvwxyz'
    let nanoid2 = customAlphabet(ALPHABET, LENGTH)

    let chars = {}
    for (let i = 0; i < COUNT; i++) {
      let id = nanoid2()
      for (let char of id) {
        if (!chars[char]) chars[char] = 0
        chars[char] += 1
      }
    }

    is(Object.keys(chars).length, ALPHABET.length)

    let max = 0
    let min = Number.MAX_SAFE_INTEGER
    for (let k in chars) {
      let distribution = (chars[k] * ALPHABET.length) / (COUNT * LENGTH)
      if (distribution > max) max = distribution
      if (distribution < min) min = distribution
    }
    ok(max - min <= 0.05)
  })

  test(`${type} / customAlphabet / changes size`, () => {
    let nanoidA = customAlphabet('a')
    is(nanoidA(10), 'aaaaaaaaaa')
  })

  test(`${type} / customAlphabet / is ready for 0 and negative size`, () => {
    is(customAlphabet('abc')(0), '')
    is(customAlphabet('abc', 0)(), '')
    is(customAlphabet('abc')(-1), '')
    is(customAlphabet('abc', 5)(-1), '')
  })

  test(`${type} / customRandom / supports generator`, () => {
    let sequence = [2, 255, 3, 7, 7, 7, 7, 7, 0, 1]
    function fakeRandom(size) {
      let bytes = []
      for (let i = 0; i < size; i += sequence.length) {
        bytes = bytes.concat(sequence.slice(0, size - i))
      }
      return bytes
    }
    let nanoid4 = customRandom('abcde', 4, fakeRandom)
    let nanoid18 = customRandom('abcde', 18, fakeRandom)
    is(nanoid4(), 'adca')
    is(nanoid18(), 'cbadcbadcbadcbadcc')
  })

  test(`${type} / customRandom / is ready for 0 size`, () => {
    let nanoid0 = customRandom('abc', 5, size => new Uint8Array(size))
    is(nanoid0(0), '')
  })

  test(`${type} / urlAlphabet / is string`, () => {
    is(typeof urlAlphabet, 'string')
  })

  test(`${type} / urlAlphabet / has no duplicates`, () => {
    for (let i = 0; i < urlAlphabet.length; i++) {
      equal(urlAlphabet.lastIndexOf(urlAlphabet[i]), i)
    }
  })

  test(`${type} / random / generates small random buffers`, () => {
    for (let i = 0; i < urlAlphabet.length; i++) {
      is(random(10).length, 10)
    }
  })

  test(`${type} / random / generates random buffers`, () => {
    let numbers = {}
    let bytes = random(1000)
    is(bytes.length, 1000)
    for (let byte of bytes) {
      if (!numbers[byte]) numbers[byte] = 0
      numbers[byte] += 1
      is(typeof byte, 'number')
      ok(byte <= 255)
      ok(byte >= 0)
    }
  })

  if (type === 'node') {
    test(`${type} / nanoid / throws on negative or too big ID size`, () => {
      // `size |= 0` maps 2**31 to a negative int32; the fillPool guard rejects it
      // instead of corrupting the pool (CVE-2026-73086).
      throws(() => nanoid(2147483648), /Wrong ID size/)
      throws(() => nanoid(-10), /Wrong ID size/)
      throws(() => nanoid(1025), /Wrong ID size/)
      // the pool is intact: legitimate calls still produce unique, valid IDs
      let a = nanoid()
      let b = nanoid()
      not.equal(a, b)
      is(a.length, 21)
    })

    test(`${type} / nanoid / keeps the pool usable after an oversized size`, () => {
      // The CVE-2026-73086 PoC: unguarded, `nanoid(2**31)` drives `poolOffset`
      // to ~-2.1e9, so every later ID reads `pool[negative]`, and
      // `undefined & 63` picks `urlAlphabet[0]` for all 21 characters. Every ID
      // in the process then degrades to the constant below.
      // A live pool is the precondition: it makes the unguarded call slip past
      // both refresh checks instead of failing inside `Buffer.allocUnsafe()`.
      is(nanoid().length, 21)
      try {
        nanoid(2147483648)
      } catch (e) {}
      let ids = new Set()
      for (let i = 0; i < 10; i++) {
        let id = nanoid()
        is.not(id, 'uuuuuuuuuuuuuuuuuuuuu')
        is(id.length, 21)
        ids.add(id)
      }
      is(ids.size, 10)
    })

    test(`${type} / random / throws on negative or too big size`, () => {
      // `random()` shares the very same pool and has no `size <= 0`
      // short-circuit, so the guard is the only thing keeping `poolOffset`
      // from moving backwards and replaying already-issued bytes.
      throws(() => random(2147483648), /Wrong ID size/)
      throws(() => random(-10), /Wrong ID size/)
      throws(() => random(1025), /Wrong ID size/)
      // the pool is intact: consecutive reads advance instead of repeating
      let first = [...random(21)].join(',')
      let second = [...random(21)].join(',')
      is(first.split(',').length, 21)
      is.not(first, second)
    })
  }

  if (type === 'node') {
    test(`${type} / proxy number / prevent collision`, () => {
      let makeProxyNumberToReproducePreviousID = () => {
        let step = 0
        return {
          valueOf() {
            // "if (!pool || pool.length < bytes) {"
            if (step === 0) {
              step++
              return 0
            }
            // "} else if (poolOffset + bytes > pool.length) {"
            if (step === 1) {
              step++
              return -Infinity
            }
            // "poolOffset += bytes"
            if (step === 2) {
              step++
              return 0
            }

            return 21
          }
        }
      }

      let ID1 = nanoid()
      let ID2 = nanoid(makeProxyNumberToReproducePreviousID())

      is.not(ID1, ID2)
    })
  }
}

// The CommonJS builds are the `require` entry points and carry their own copy
// of the generator loop, so they need the same 0 and negative size coverage.
for (let type of ['node', 'browser']) {
  let { customAlphabet, customRandom, nanoid, random } =
    type === 'node' ? require('../index.cjs') : require('../index.browser.cjs')

  test(`${type} cjs / customAlphabet / is ready for 0 and negative size`, () => {
    is(customAlphabet('abc')(0), '')
    is(customAlphabet('abc', 0)(), '')
    is(customAlphabet('abc')(-1), '')
    is(customAlphabet('abc', 5)(-1), '')
  })

  test(`${type} cjs / customRandom / is ready for 0 size`, () => {
    let nanoid0 = customRandom('abc', 5, size => new Uint8Array(size))
    is(nanoid0(0), '')
  })

  if (type === 'node') {
    // `index.cjs` keeps its own `pool`/`poolOffset` pair, so a guard added only
    // to `index.js` would leave every `require('nanoid')` consumer exploitable.
    test(`${type} cjs / nanoid / throws on negative or too big ID size`, () => {
      throws(() => nanoid(2147483648), /Wrong ID size/)
      throws(() => nanoid(-10), /Wrong ID size/)
      throws(() => nanoid(1025), /Wrong ID size/)
      let a = nanoid()
      let b = nanoid()
      not.equal(a, b)
      is(a.length, 21)
    })

    test(`${type} cjs / nanoid / keeps the pool usable after an oversized size`, () => {
      // Prime the pool first — see the ESM twin above for why that matters.
      is(nanoid().length, 21)
      try {
        nanoid(2147483648)
      } catch (e) {}
      let ids = new Set()
      for (let i = 0; i < 10; i++) {
        let id = nanoid()
        is.not(id, 'uuuuuuuuuuuuuuuuuuuuu')
        is(id.length, 21)
        ids.add(id)
      }
      is(ids.size, 10)
    })

    test(`${type} cjs / random / throws on negative or too big size`, () => {
      throws(() => random(2147483648), /Wrong ID size/)
      throws(() => random(-10), /Wrong ID size/)
      throws(() => random(1025), /Wrong ID size/)
      is(random(21).length, 21)
    })

    test(`${type} cjs / random / keeps the pool advancing after a negative size`, () => {
      // A negative `random()` size walks `poolOffset` backwards, which makes the
      // next reads replay bytes that were already handed out (ID collisions).
      let before = [...random(21)].join(',')
      try {
        random(-21)
      } catch (e) {}
      let after = [...random(21)].join(',')
      is.not(before, after)
    })
  }
}

test.run()
