function document(text, start) {
  try {
    return { text, start, value: JSON.parse(text) }
  } catch {
    return null
  }
}

export function jsonDocuments(text, strictLines = false) {
  if (!strictLines) {
    if (!/^\s*[\[{\"]/.test(text)) return null
    const parsed = document(text, 0)
    if (parsed) return [parsed]
    if (!text.includes('\n')) return null
  }

  const documents = []
  let start = 0
  let line = 1
  while (start < text.length) {
    const newline = text.indexOf('\n', start)
    const end = newline < 0 ? text.length : newline + 1
    const raw = text.slice(start, end)
    if (raw.trim()) {
      const parsed = document(raw, start)
      if (!parsed) {
        if (strictLines) throw new Error(`Invalid JSONL record on line ${line}`)
        return null
      }
      documents.push(parsed)
    }
    start = end
    line++
  }
  return documents.length || strictLines ? documents : null
}

export function mapJsonFindings(literal, findings, start) {
  if (!findings.length) return []
  const boundaries = new Map()
  for (const finding of findings) {
    boundaries.set(finding.start, 0)
    boundaries.set(finding.end, 0)
  }
  let decoded = 0
  for (let index = 1; index < literal.length;) {
    if (boundaries.has(decoded)) boundaries.set(decoded, start + index)
    if (index === literal.length - 1) break
    index += literal[index] === '\\' ? (literal[index + 1] === 'u' ? 6 : 2) : 1
    decoded++
  }
  return findings.map(finding => ({
    ...finding,
    start: boundaries.get(finding.start),
    end: boundaries.get(finding.end),
    ...(finding.jsonDepth === undefined ? {} : { jsonDepth: finding.jsonDepth + 1 }),
  }))
}

export function assertJsonStructure(before, after, strictLines = false) {
  const original = jsonDocuments(before) ?? (strictLines ? jsonDocuments(before, true) : null)
  if (!original) return
  const redacted = jsonDocuments(after) ?? (strictLines ? jsonDocuments(after, true) : null)
  if (!redacted || original.length !== redacted.length) {
    throw new Error('Redaction would change JSON structure or lose records')
  }
  for (let index = 0; index < original.length; index++) {
    compareValues(original[index].value, redacted[index].value)
  }
}

function compareValues(before, after) {
  const fail = () => { throw new Error('Redaction would change JSON structure or merge object entries') }
  if (typeof before === 'string') {
    if (typeof after !== 'string') fail()
    assertJsonStructure(before, after)
  } else if (Array.isArray(before)) {
    if (!Array.isArray(after) || before.length !== after.length) fail()
    before.forEach((value, index) => compareValues(value, after[index]))
  } else if (before !== null && typeof before === 'object') {
    if (after === null || typeof after !== 'object' || Array.isArray(after)) fail()
    const beforeKeys = Object.keys(before)
    const afterKeys = Object.keys(after)
    if (beforeKeys.length !== afterKeys.length) fail()
    beforeKeys.forEach((key, index) => {
      compareValues(key, afterKeys[index])
      compareValues(before[key], after[afterKeys[index]])
    })
  } else if (before !== after && !(typeof after === 'string' && /^«BROOM:[\w-]+:[a-f0-9]{8}»$/.test(after))) {
    fail()
  }
}
