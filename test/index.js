'use strict'

const assert = require('node:assert/strict')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const { afterEach, beforeEach, describe, it } = require('node:test')

const fixtures = require('haraka-test-fixtures')

const _set_up = () => {
  this.plugin = new fixtures.plugin('clamd')
  this.plugin.register()
  this.connection = fixtures.connection.createConnection()
  this.connection.init_transaction()
}

const runHook = (call) => new Promise((resolve) => call((...a) => resolve(a)))
const results = () => this.connection.transaction.results.get('clamd')
const skipLen = () => results().skip.length

describe('plugins/clamd', () => {
  describe('load_clamd_ini', () => {
    beforeEach(_set_up)

    it('none', () => {
      assert.deepEqual(this.plugin.skip_list, [])
    })

    it('defaults', () => {
      const cfg = this.plugin.cfg.main
      assert.equal(cfg.clamd_socket, 'localhost:3310')
      assert.equal(cfg.timeout, 30)
      assert.equal(cfg.connect_timeout, 10)
      assert.equal(cfg.max_size, 26214400)
      assert.equal(cfg.only_with_attachments, false)
      assert.equal(cfg.randomize_host_order, false)
    })

    it('reject opts', () => {
      const yes = [
        'Encrypted.',
        'Heuristics.Structured.',
        'Heuristics.Structured.CreditCardNumber',
        'Broken.Executable.',
        'PUA.',
        'Heuristics.OLE2.ContainsMacros',
        'Heuristics.Safebrowsing.',
        'Heuristics.Safebrowsing.Suspected-phishing_safebrowsing.clamav.net',
        'Sanesecurity.Junk.50402.UNOFFICIAL',
      ]
      const no = [
        'Sanesecurity.UNOFFICIAL.oops',
        'Phishing',
        'Heuristics.Phishing.Email.SpoofedDomain',
        'Suspect.Executable',
        'MattWuzHere',
      ]
      for (const v of yes) assert.ok(this.plugin.rejectRE.test(v), v)
      for (const v of no) assert.ok(!this.plugin.rejectRE.test(v), v)
    })
  })

  describe('load_clamd_ini alias', () => {
    beforeEach(_set_up)

    it('maps only_with_attachment -> only_with_attachments', () => {
      const orig = this.plugin.config.get.bind(this.plugin.config)
      this.plugin.config.get = (name, ...rest) => {
        const cfg = orig(name, ...rest)
        if (name === 'clamd.ini') cfg.main.only_with_attachment = 'true'
        return cfg
      }
      this.plugin.load_clamd_ini()
      assert.equal(this.plugin.cfg.main.only_with_attachments, true)
    })
  })

  describe('hook_data', () => {
    beforeEach(_set_up)

    const runData = () =>
      runHook((next) => this.plugin.hook_data(next, this.connection))

    it('attachment hook flags clamd_found_attachment', async () => {
      this.plugin.cfg.main.only_with_attachments = true
      this.connection.transaction.attachment_hooks = (cb) =>
        cb('application/pdf', 'evil.pdf', {})
      await runData()
      assert.equal(
        this.connection.transaction.notes.clamd_found_attachment,
        true,
      )
    })

    it('only_with_attachments, false', async () => {
      assert.equal(this.plugin.cfg.main.only_with_attachments, false)
      await runData()
      assert.equal(this.connection.transaction.parse_body, false)
    })

    it('only_with_attachments, true', async () => {
      this.plugin.cfg.main.only_with_attachments = true
      this.connection.transaction.attachment_hooks = () => {}
      await runData()
      assert.equal(this.plugin.cfg.main.only_with_attachments, true)
      assert.equal(this.connection.transaction.parse_body, true)
    })
  })

  describe('hook_data_post', () => {
    beforeEach(_set_up)

    const runPost = () =>
      runHook((next) => this.plugin.hook_data_post(next, this.connection))

    it('skip attachment', async () => {
      this.connection.transaction.notes = { clamd_found_attachment: false }
      this.plugin.cfg.main.only_with_attachments = true
      await runPost()
      assert.ok(skipLen() > 0)
    })

    it('skip authenticated', async () => {
      this.connection.notes.auth_user = 'user'
      this.plugin.cfg.check.authenticated = false
      await runPost()
      assert.ok(skipLen() > 0)
    })

    it('checks local IP', async () => {
      this.connection.remote.is_local = true
      this.plugin.cfg.check.local_ip = true
      await runPost()
      assert.equal(skipLen(), 0)
    })

    it('skips local IP', async () => {
      this.connection.remote.is_local = true
      this.plugin.cfg.check.local_ip = false
      await runPost()
      assert.ok(skipLen() > 0)
    })

    it('checks private IP', async () => {
      this.connection.remote.is_private = true
      this.plugin.cfg.check.private_ip = true
      await runPost()
      assert.equal(skipLen(), 0)
    })

    it('skips private IP', async () => {
      this.connection.remote.is_private = true
      this.plugin.cfg.check.private_ip = false
      await runPost()
      assert.ok(skipLen() > 0)
    })

    it('checks public ip', async () => {
      await runPost()
      assert.equal(skipLen(), 0)
    })

    it('skip localhost if check.local_ip = false and check.private_ip = true', async () => {
      this.connection.remote.is_local = true
      this.connection.remote.is_private = true
      this.plugin.cfg.check.local_ip = false
      this.plugin.cfg.check.private_ip = true
      await runPost()
      assert.ok(skipLen() > 0)
    })

    it('checks localhost if check.local_ip = true and check.private_ip = false', async () => {
      this.connection.remote.is_local = true
      this.connection.remote.is_private = true
      this.plugin.cfg.check.local_ip = true
      this.plugin.cfg.check.private_ip = false
      await runPost()
      assert.equal(skipLen(), 0)
    })

    it('message too big', async () => {
      this.connection.transaction.data_bytes = 513
      this.plugin.cfg.main.max_size = 512
      await runPost()
      assert.ok(skipLen() > 0)
    })
  })

  describe('send_clamd_predata', () => {
    beforeEach(_set_up)

    it('writes the proper commands to clamd socket', async () => {
      await new Promise((resolve) => {
        const server = net.createServer((socket) => {
          socket.on('data', (data) => {
            assert.ok(
              data.toString(),
              `zINSTREAM\0Received: from Haraka clamd plugin\r\n`,
            )
          })
          socket.on('end', resolve)
        })
        server.listen(65535, () => {
          const client = new net.Socket()
          client.connect(65535, () => {
            this.plugin.send_clamd_predata(client, () => client.end())
          })
        })
        server.unref()
      })
    })
  })

  describe('load_excludes', () => {
    beforeEach(_set_up)

    it('parses wildcard/regex skips and excludes', () => {
      this.plugin.config.get = () => [
        'Eicar-Test-*', // wildcard skip
        '/^Foo\\.Bar/', // regex skip
        '!Sanesecurity-*', // wildcard exclude
        '!/^PUA\\./', // regex exclude
        '!/([/', // invalid regex exclude -> logged & skipped
      ]
      this.plugin.load_excludes()
      assert.equal(this.plugin.skip_list.length, 2)
      assert.equal(this.plugin.skip_list_exclude.length, 2)
      assert.ok(this.plugin.skip_list[0].test('Eicar-Test-Signature'))
      assert.ok(this.plugin.skip_list[1].test('Foo.Bar.Thing'))
      assert.ok(this.plugin.skip_list_exclude[0].test('Sanesecurity-Foo'))
      assert.ok(this.plugin.skip_list_exclude[1].test('PUA.Win.Foo'))
      assert.ok(!this.plugin.skip_list_exclude[1].test('NotPUA.Win.Foo'))
    })

    it('logs and skips an invalid regex entry', () => {
      this.plugin.config.get = () => ['/([/']
      assert.doesNotThrow(() => this.plugin.load_excludes())
      assert.equal(this.plugin.skip_list.length, 0)
    })
  })

  describe('hook_data_post (full clamd exchange)', () => {
    let server

    const primeTxn = () =>
      new Promise((done) => {
        _set_up()
        const txn = this.connection.transaction
        txn.message_stream.add_line('Subject: hi\r\n')
        txn.message_stream.add_line('\r\n')
        txn.message_stream.add_line('body\r\n')
        txn.message_stream.add_line_end(done)
      })

    const startClamd = (reply, host = '127.0.0.1') =>
      new Promise((resolve) => {
        server = net.createServer((s) => {
          s.on('data', () => {})
          s.on('end', () => s.end(reply))
        })
        if (host.startsWith('/')) {
          server.listen(host, () => resolve(host))
        } else {
          server.listen(0, host, () => {
            const { port } = server.address()
            const fmt = host.includes(':')
              ? `[${host}]:${port}`
              : `${host}:${port}`
            resolve(fmt)
          })
        }
      })

    const run = async ({ reply, host, tweak } = {}) => {
      await primeTxn()
      if (reply !== undefined) {
        this.plugin.cfg.main.clamd_socket = await startClamd(reply, host)
      }
      tweak?.(this.plugin, this.connection)
      return runHook((next) =>
        this.plugin.hook_data_post(next, this.connection),
      )
    }

    afterEach((t, done) => {
      const s = server
      server = null
      if (s && s.listening) return s.close(done)
      done()
    })

    it('passes a clean message', async () => {
      const args = await run({ reply: 'stream: OK\n' })
      assert.deepEqual(args, [])
      assert.ok(results().pass.includes('clean'))
    })

    it('DENYs an infected message', async () => {
      const [code, msg] = await run({
        reply: 'stream: Eicar-Test-Signature FOUND\n',
      })
      assert.equal(code, DENY)
      assert.match(msg, /infected with Eicar-Test-Signature/)
    })

    it('accepts a virus when reject.virus is false', async () => {
      const args = await run({
        reply: 'stream: Eicar-Test FOUND\n',
        tweak: (p) => {
          p.cfg.reject.virus = false
        },
      })
      assert.deepEqual(args, [])
      assert.ok(results().fail.includes('Eicar-Test'))
    })

    it('continues past a clamd size-limit error', async () => {
      const args = await run({ reply: 'INSTREAM size limit exceeded\n' })
      assert.deepEqual(args, [])
      assert.ok(
        results()
          .err.join()
          .match(/size limit/),
      )
    })

    it('virus with reject-option disabled -> header + accept', async () => {
      // Phishing is disabled by default: matches allRE but not rejectRE
      const args = await run({
        reply: 'stream: Heuristics.Phishing.Email FOUND\n',
      })
      assert.deepEqual(args, [])
      assert.match(
        this.connection.transaction.header.get('X-Haraka-Virus'),
        /Heuristics\.Phishing\.Email/,
      )
    })

    it('connects over a unix domain socket', async () => {
      const sock = path.join(os.tmpdir(), `clamd-test-${process.pid}.sock`)
      const args = await run({ reply: 'stream: OK\n', host: sock })
      assert.deepEqual(args, [])
    })

    it('skip_list_exclude match -> DENY', async () => {
      const [code] = await run({
        reply: 'stream: Eicar-Test FOUND\n',
        tweak: (p) => {
          p.skip_list_exclude = [/Eicar/]
        },
      })
      assert.equal(code, DENY)
    })

    it('skip_list match -> header + accept', async () => {
      const args = await run({
        reply: 'stream: Eicar-Test FOUND\n',
        tweak: (p) => {
          p.skip_list = [/Eicar/]
        },
      })
      assert.deepEqual(args, [])
      assert.match(
        this.connection.transaction.header.get('X-Haraka-Virus'),
        /Eicar-Test/,
      )
    })

    it('unknown clamd result -> DENYSOFT', async () => {
      const [code] = await run({
        reply: 'mystery response\n',
        tweak: (p) => {
          p.cfg.reject.error = true
        },
      })
      assert.equal(code, DENYSOFT)
    })

    it('honors randomize_host_order across a host list', async () => {
      const args = await run({
        reply: 'stream: OK\n',
        tweak: (p) => {
          p.cfg.main.clamd_socket = `${p.cfg.main.clamd_socket} ${p.cfg.main.clamd_socket}`
          p.cfg.main.randomize_host_order = true
        },
      })
      assert.deepEqual(args, [])
    })

    it('skips relaying senders when check.relay=false', async () => {
      const args = await run({
        tweak: (p, c) => {
          c.relaying = true
          p.cfg.check.relay = false
        },
      })
      assert.deepEqual(args, [])
      assert.ok(results().skip.includes('relay'))
    })

    it('connects to an IPv6 literal host', async () => {
      const args = await run({ reply: 'stream: OK\n', host: '::1' })
      assert.deepEqual(args, [])
    })

    it('DENYSOFTs when no clamd host is reachable', async () => {
      const args = await run({
        tweak: (p) => {
          p.cfg.main.clamd_socket = '127.0.0.1:1'
          p.cfg.reject.error = true
        },
      })
      assert.equal(args[0], DENYSOFT)
    })
  })
})
