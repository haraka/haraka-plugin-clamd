// clamd

const net = require('node:net')

const utils = require('haraka-utils')
const net_utils = require('haraka-net-utils')

exports.load_excludes = function () {
  this.loginfo('Loading excludes file')
  const list = this.config.get('clamd.excludes', 'list', () => {
    this.load_excludes()
  })

  const exclude = []
  const skip = []
  for (const element of list) {
    try {
      const { negated, re } = parse_exclude(element)
      ;(negated ? exclude : skip).push(re)
    } catch (e) {
      this.logerror(`${e.message} (entry: ${element})`)
    }
  }

  this.skip_list_exclude = exclude
  this.skip_list = skip
}

function parse_exclude(element) {
  const negated = element[0] === '!'
  const body = negated ? element.slice(1) : element
  const re =
    body[0] === '/'
      ? new RegExp(body.slice(1, -1), 'i')
      : new RegExp(utils.wildcard_to_regexp(body), 'i')
  return { negated, re }
}

exports.load_clamd_ini = function () {
  this.cfg = this.config.get(
    'clamd.ini',
    {
      booleans: [
        '-main.randomize_host_order',
        '-main.only_with_attachments',
        '+reject.virus',
        '+reject.error',

        '+reject.Broken.Executable',
        '+reject.Structured', // DLP options
        '+reject.Encrypted',
        '+reject.PUA',
        '+reject.OLE2',
        '+reject.Safebrowsing',
        '+reject.UNOFFICIAL',

        // prone to false positives.
        '-reject.Phishing',

        '+check.authenticated',
        '+check.relay',
        '+check.private_ip',
        '+check.local_ip',
      ],
    },
    () => {
      this.load_clamd_ini()
    },
  )

  const defaults = {
    clamd_socket: 'localhost:3310',
    timeout: 30,
    connect_timeout: 10,
    max_size: 26214400,
  }

  for (const key in defaults) {
    if (this.cfg.main[key] === undefined) {
      this.cfg.main[key] = defaults[key]
    }
  }

  const rejectPatterns = {
    'Broken.Executable': '^Broken\\.Executable\\.?',
    Encrypted: '^Encrypted\\.',
    PUA: '^PUA\\.',
    Structured: '^Heuristics\\.Structured\\.',
    OLE2: '^Heuristics\\.OLE2\\.ContainsMacros',
    Safebrowsing: '^Heuristics\\.Safebrowsing\\.',
    Phishing: '^Heuristics\\.Phishing\\.',
    UNOFFICIAL: '\\.UNOFFICIAL$',
  }

  const all_reject_opts = []
  const enabled_reject_opts = []
  for (const opt of Object.keys(rejectPatterns)) {
    all_reject_opts.push(rejectPatterns[opt])
    if (!this.cfg.reject[opt]) continue
    enabled_reject_opts.push(rejectPatterns[opt])
  }

  if (enabled_reject_opts.length) {
    this.allRE = new RegExp(all_reject_opts.join('|'))
    this.rejectRE = new RegExp(enabled_reject_opts.join('|'))
  }

  // resolve mismatch between docs (...attachment) and code (...attachments)
  if (this.cfg.main.only_with_attachment !== undefined) {
    this.cfg.main.only_with_attachments = !!this.cfg.main.only_with_attachment
  }
}

exports.register = function () {
  this.load_excludes()
  this.load_clamd_ini()
}

exports.hook_data = function (next, connection) {
  if (!this.cfg.main.only_with_attachments) return next()

  if (!this.should_check(connection)) return next()

  const txn = connection.transaction
  txn.parse_body = true
  txn.attachment_hooks((ctype, filename, body) => {
    connection.logdebug(this, `found ctype=${ctype}, filename=${filename}`)
    txn.notes.clamd_found_attachment = true
  })

  next()
}

exports.hook_data_post = async function (next, connection) {
  const plugin = this
  if (!plugin.should_check(connection)) return next()

  const txn = connection.transaction
  const { cfg } = plugin

  if (cfg.main.only_with_attachments && !txn.notes.clamd_found_attachment) {
    connection.logdebug(plugin, 'skipping: no attachments found')
    txn.results.add(plugin, { skip: 'no attachments' })
    return next()
  }

  if (txn.data_bytes > cfg.main.max_size) {
    txn.results.add(plugin, { skip: 'exceeds max size', emit: true })
    return next()
  }

  const hosts = cfg.main.clamd_socket.split(/[,; ]+/)
  if (cfg.main.randomize_host_order) hosts.sort(() => 0.5 - Math.random())

  for (let i = 0; i < hosts.length; i++) {
    const host = hosts[i]
    const isLast = i === hosts.length - 1
    connection.logdebug(plugin, `trying host: ${host}`)

    const outcome = await scan_against(plugin, connection, txn, host)

    if (outcome.kind === 'connect_failed') {
      connection.logerror(
        plugin,
        `Connection to ${host} failed: ${outcome.reason}`,
      )
      continue
    }

    if (outcome.kind === 'post_connect_error') {
      if (!isLast) {
        connection.logwarn(plugin, `error on host ${host}: ${outcome.reason}`)
        continue
      }
      txn.results.add(plugin, {
        err: `error on host ${host}: ${outcome.reason}`,
      })
      if (!cfg.reject.error) return next()
      return next(DENYSOFT, 'Virus scanner error')
    }

    if (outcome.kind === 'scan_timeout') {
      txn.results.add(plugin, { err: 'clamd timed out' })
      if (!cfg.reject.error) return next()
      return next(DENYSOFT, 'Virus scanner timed out')
    }

    const parsed = parse_clamd_result(outcome.line)

    if (parsed.kind === 'clean') {
      txn.results.add(plugin, { pass: 'clean', emit: true })
      return next()
    }

    if (parsed.kind === 'size_limit') {
      txn.results.add(plugin, {
        err: 'INSTREAM size limit exceeded. Check StreamMaxLength in clamd.conf',
      })
      return next()
    }

    if (parsed.kind === 'virus') {
      txn.results.add(plugin, { fail: parsed.virus || 'virus', emit: true })
      const decision = decide_virus_action(plugin, parsed.virus)
      if (decision.matched_exclusion) {
        connection.logwarn(plugin, `${parsed.virus} matches exclusion`)
      }
      if (decision.action === 'pass') {
        if (decision.tag) txn.add_header('X-Haraka-Virus', parsed.virus)
        return next()
      }
      return next(DENY, `Message is infected with ${parsed.virus || 'UNKNOWN'}`)
    }

    // unknown result
    if (!isLast) {
      connection.logwarn(
        plugin,
        `unknown result: '${outcome.line}' from host ${host}`,
      )
      continue
    }
    txn.results.add(plugin, {
      err: `unknown result: '${outcome.line}' from host ${host}`,
    })
    if (!cfg.reject.error) return next()
    return next(DENYSOFT, 'Error running virus scanner')
  }

  txn.results.add(plugin, { err: 'connecting' })
  if (!cfg.reject.error) return next()
  return next(DENYSOFT, 'Error connecting to virus scanner')
}

function scan_against(plugin, connection, txn, host) {
  return new Promise((resolve) => {
    const { cfg } = plugin
    const socket = new net.Socket()
    net_utils.add_line_processor(socket)

    let connected = false
    let lastLine = ''
    let settled = false
    let scanTimer = null

    const settle = (outcome) => {
      if (settled) return
      settled = true
      clearTimeout(scanTimer)
      resolve(outcome)
    }

    socket.setTimeout((cfg.main.connect_timeout || 10) * 1000)

    socket.on('timeout', () => {
      // Only fires during the connection phase; we disable the socket timeout
      // after connect and switch to an absolute deadline (see below).
      socket.destroy()
      settle({ kind: 'connect_failed', reason: 'timeout' })
    })

    socket.on('error', (err) => {
      socket.destroy()
      settle({
        kind: connected ? 'post_connect_error' : 'connect_failed',
        reason: err.message,
      })
    })

    socket.on('connect', () => {
      connected = true
      // socket.setTimeout is an inactivity timer: every write during
      // message_stream.pipe() resets it, so it cannot bound the total scan
      // duration. Use an absolute deadline instead.
      socket.setTimeout(0)
      scanTimer = setTimeout(() => {
        settle({ kind: 'scan_timeout' })
        socket.destroy()
      }, (cfg.main.timeout || 30) * 1000)
      const hp = socket.address()
      const addressInfo = hp === null ? '' : ` ${hp.address}:${hp.port}`
      connection.logdebug(plugin, `connected to host${addressInfo}`)
      plugin.send_clamd_predata(socket, () => {
        txn.message_stream.pipe(socket, { clamd_style: true })
      })
    })

    socket.on('line', (line) => {
      connection.logprotocol(plugin, `C:${line.replace(/[^\x20-\x7e]/g, '')}`)
      lastLine = line.replace(/\r?\n/, '')
    })

    socket.on('end', () => settle({ kind: 'done', line: lastLine }))

    clamd_connect(socket, host)
  })
}

function parse_clamd_result(line) {
  if (/^stream: OK/.test(line)) return { kind: 'clean' }
  const m = /^stream: (\S+) FOUND/.exec(line)
  if (m) return { kind: 'virus', virus: m[1] }
  if (/size limit exceeded/.test(line)) return { kind: 'size_limit' }
  return { kind: 'unknown' }
}

// Decide what to do with a virus name based on plugin config:
//   - tag: true means add the X-Haraka-Virus header alongside the action
//   - matched_exclusion: true means the skip_list rescued the message
function decide_virus_action(plugin, virus) {
  // A virus that matches a known category whose reject flag is off → pass + tag.
  if (
    virus &&
    plugin.rejectRE &&
    plugin.allRE.test(virus) &&
    !plugin.rejectRE.test(virus)
  ) {
    return { action: 'pass', tag: true }
  }
  if (!plugin.cfg.reject.virus) return { action: 'pass', tag: false }
  // skip_list_exclude wins over skip_list (forces a reject even if skip_list would match).
  if (plugin.skip_list_exclude.some((re) => re.test(virus))) {
    return { action: 'reject' }
  }
  for (const re of plugin.skip_list) {
    if (re.test(virus))
      return { action: 'pass', tag: true, matched_exclusion: true }
  }
  return { action: 'reject' }
}

exports.should_check = function (connection) {
  if (!connection?.transaction) return false

  const { cfg } = this
  const { remote, notes, relaying } = connection
  const txn = connection.transaction

  const reasons = []
  if (cfg.check.authenticated === false && notes.auth_user)
    reasons.push('authed')
  if (cfg.check.relay === false && relaying) reasons.push('relay')
  if (cfg.check.local_ip === false && remote.is_local) reasons.push('local_ip')
  // A local IP is also a private IP. If the operator has opted into local_ip
  // checking, don't separately add a private_ip skip for the same connection.
  if (
    cfg.check.private_ip === false &&
    remote.is_private &&
    !(cfg.check.local_ip === true && remote.is_local)
  ) {
    reasons.push('private_ip')
  }

  for (const skip of reasons) txn.results.add(this, { skip })
  return reasons.length === 0
}

exports.send_clamd_predata = (socket, cb) => {
  socket.write('zINSTREAM\0', () => {
    const received = 'Received: from Haraka clamd plugin\r\n'
    const buf = Buffer.alloc(received.length + 4)
    buf.writeUInt32BE(received.length, 0)
    buf.write(received, 4)
    socket.write(buf, cb)
  })
}

function clamd_connect(socket, host) {
  if (host.match(/^\//)) {
    socket.connect(host) // starts with /, unix socket
    return
  }

  const match = /^\[([^\] ]+)\](?::(\d+))?/.exec(host)
  if (match) {
    socket.connect(match[2] || 3310, match[1]) // IPv6 literal
    return
  }

  // IP:port, hostname:port or hostname
  const hostport = host.split(/:/)
  socket.connect(hostport[1] || 3310, hostport[0])
}
