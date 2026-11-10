import { test } from 'node:test'
import assert from 'node:assert/strict'

import { RULES } from '../src/rules.mjs'
import { scanText } from '../src/detector.mjs'
import { redactText, buildPlaceholder } from '../src/redactor.mjs'

const SECRET = 'ghp_' + '1234567890abcdefABCDEF1234567890abcd'
const DB = 'postgres://' + 'reader:Example123@database.example.invalid/app'

function clean(text, extras = []) {
  return redactText(text, scanText(text, RULES, extras))
}

test('quoted database URLs preserve JSON escaping and surrounding text', () => {
  const original = { text: `connect("${DB}")`, keep: { count: 4, ok: true, empty: null } }
  const result = clean(JSON.stringify(original))
  const parsed = JSON.parse(result.text)
  assert.equal(result.applied, 1)
  assert.equal(parsed.text, `connect("${buildPlaceholder('db-url', DB)}")`)
  assert.deepEqual(parsed.keep, original.keep)
  assert.equal(scanText(result.text, RULES).length, 0)
})

test('serialized tool arguments remain valid through multiple JSON encodings', () => {
  const argumentsText = JSON.stringify({ url: DB, keep: [1, true, null] })
  const original = JSON.stringify({ arguments: JSON.stringify({ arguments: argumentsText }) })
  const result = clean(original)
  const nested = JSON.parse(JSON.parse(JSON.parse(result.text).arguments).arguments)
  assert.equal(nested.url, buildPlaceholder('db-url', DB))
  assert.deepEqual(nested.keep, [1, true, null])
  assert.equal(scanText(result.text, RULES).length, 0)
})

test('private-key patterns cannot cross JSONL records', () => {
  const records = [
    { type: 'assistant', text: 'look for -----BEGIN PRIVATE KEY-----', keep: 1 },
    { type: 'user', text: 'then -----END PRIVATE KEY-----', keep: 2 },
  ]
  const original = records.map(record => JSON.stringify(record)).join('\n') + '\n'
  const result = clean(original)
  assert.equal(result.applied, 0)
  assert.equal(result.text, original)
  assert.deepEqual(result.text.trim().split('\n').map(line => JSON.parse(line)), records)
})

test('private-key patterns cannot cross separate JSON fields', () => {
  const original = JSON.stringify({ begin: '-----BEGIN PRIVATE KEY-----', keep: 42, end: '-----END PRIVATE KEY-----' })
  assert.deepEqual(clean(original), { text: original, applied: 0 })
})

test('complete private keys within a JSON string are redacted without losing records', () => {
  const pem = '-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END PRIVATE KEY-----'
  const original = JSON.stringify({ text: pem, keep: 1 }) + '\n' + JSON.stringify({ keep: 2 }) + '\n'
  const result = clean(original)
  const records = result.text.trim().split('\n').map(line => JSON.parse(line))
  assert.equal(result.applied, 1)
  assert.deepEqual(records, [{ text: buildPlaceholder('private-key', pem), keep: 1 }, { keep: 2 }])
})

test('secrets in serialized dictionary keys preserve every cache entry', () => {
  const key = JSON.stringify({ url: DB })
  const original = JSON.stringify({ [key]: { keep: 3 }, unrelated: { keep: 4 } })
  const parsed = JSON.parse(clean(original).text)
  const keys = Object.keys(parsed)
  assert.equal(keys.length, 2)
  assert.deepEqual(JSON.parse(keys[0]), { url: buildPlaceholder('db-url', DB) })
  assert.deepEqual(Object.values(parsed), [{ keep: 3 }, { keep: 4 }])
})

test('Unicode-escaped secrets are detected with offsets in the original input', () => {
  const original = JSON.stringify({ text: `😀 "quoted" \\prefix\nkey ${SECRET}`, keep: '😀' }).replace('ghp_', '\\u0067hp_')
  const result = clean(original)
  const parsed = JSON.parse(result.text)
  assert.equal(result.applied, 1)
  assert.equal(parsed.text, `😀 "quoted" \\prefix\nkey ${buildPlaceholder('github-pat', SECRET)}`)
  assert.equal(parsed.keep, '😀')
})

test('extra literals containing quotes, backslashes and newlines redact safely', () => {
  const secret = 'known "quoted" \\secret\nsecond line'
  const result = clean(JSON.stringify({ text: `before ${secret} after`, keep: false }), [secret])
  assert.equal(result.applied, 1)
  assert.deepEqual(JSON.parse(result.text), { text: `before ${buildPlaceholder('extra-0', secret)} after`, keep: false })
})

test('extra numeric secrets become valid JSON strings without changing other scalars', () => {
  const result = clean(JSON.stringify({ pin: 8765432190, keep: [true, null, 7] }), ['8765432190'])
  assert.deepEqual(JSON.parse(result.text), { pin: buildPlaceholder('extra-0', '8765432190'), keep: [true, null, 7] })
})

test('numeric secrets inside serialized JSON retain valid nested JSON', () => {
  const original = JSON.stringify({ arguments: JSON.stringify({ pin: 8765432190, keep: 7 }) })
  const parsed = JSON.parse(clean(original, ['8765432190']).text)
  assert.deepEqual(JSON.parse(parsed.arguments), { pin: buildPlaceholder('extra-0', '8765432190'), keep: 7 })
})

test('existing password placeholders are not detected as fresh passwords', () => {
  const placeholder = '«BROOM:labeled-password:0123abcd»'
  assert.deepEqual(scanText(placeholder, RULES), [])
  assert.deepEqual(scanText(JSON.stringify({ text: placeholder }), RULES), [])
  assert.equal(scanText(`${placeholder} password: p7Q2rX9m`, RULES).length, 1)
  assert.equal(scanText('password: 0123abcd', RULES).length, 1)
  assert.equal(scanText('«BROOM:labeled-password:p7Q2rX9m»', RULES).length, 1)
})

test('redaction refuses dictionary-key collisions instead of losing entries', () => {
  const original = JSON.stringify({ [SECRET]: { keep: 1 }, [buildPlaceholder('github-pat', SECRET)]: { keep: 2 } })
  assert.throws(() => clean(original), /collis|structure|entries/i)
})

test('unaffected JSON whitespace, line endings and scalar values stay unchanged', () => {
  const original = '{ "keep": [null, true, 12, "ordinary text"] }\r\n\r\n'
  assert.deepEqual(clean(original), { text: original, applied: 0 })
})

test('numeric extras keep pretty-printed JSON valid', () => {
  const original = JSON.stringify({ pin: 8765432190, keep: { count: 7 } }, null, 2)
  const result = clean(original, ['8765432190'])
  assert.deepEqual(JSON.parse(result.text), { pin: buildPlaceholder('extra-0', '8765432190'), keep: { count: 7 } })
})
