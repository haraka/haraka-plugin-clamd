'use strict'

const assert = require('node:assert')
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

describe('plugins/clamd', () => {
  describe('load_clamd_ini', () => {
    beforeEach(_set_up)

    it('none', () => {
      assert.deepEqual([], this.plugin.skip_list)
    })

    it('defaults', () => {
      const cfg = this.plugin.cfg.main
      assert.equal('localhost:3310', cfg.clamd_socket)
      assert.equal(30, cfg.timeout)
      assert.equal(10, cfg.connect_timeout)
      assert.equal(26214400, cfg.max_size)
      assert.equal(false, cfg.only_with_attachments)
      assert.equal(false, cfg.randomize_host_order)
    })

    it('reject opts', () => {
      assert.equal(true, this.plugin.rejectRE.test('Encrypted.'))
      assert.equal(true, this.plugin.rejectRE.test('Heuristics.Structured.'))
      assert.equal(
        true,
        this.plugin.rejectRE.test('Heuristics.Structured.CreditCardNumber'),
      )
      assert.equal(true, this.plugin.rejectRE.test('Broken.Executable.'))
      assert.equal(true, this.plugin.rejectRE.test('PUA.'))
      assert.equal(
        true,
        this.plugin.rejectRE.test('Heuristics.OLE2.ContainsMacros'),
      )
      assert.equal(true, this.plugin.rejectRE.test('Heuristics.Safebrowsing.'))
      assert.equal(
        true,
        this.plugin.rejectRE.test(
          'Heuristics.Safebrowsing.Suspected-phishing_safebrowsing.clamav.net',
        ),
      )
      assert.equal(
        true,
        this.plugin.rejectRE.test('Sanesecurity.Junk.50402.UNOFFICIAL'),
      )
      assert.equal(
        false,
        this.plugin.rejectRE.test('Sanesecurity.UNOFFICIAL.oops'),
      )
      assert.equal(false, this.plugin.rejectRE.test('Phishing'))
      assert.equal(
        false,
        this.plugin.rejectRE.test('Heuristics.Phishing.Email.SpoofedDomain'),
      )
      assert.equal(false, this.plugin.rejectRE.test('Suspect.Executable'))
      assert.equal(false, this.plugin.rejectRE.test('MattWuzHere'))
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

    it('attachment hook flags clamd_found_attachment', async () => {
      this.plugin.cfg.main.only_with_attachments = true
      this.connection.transaction.attachment_hooks = (cb) =>
        cb('application/pdf', 'evil.pdf', {})
      await new Promise((resolve) => {
        this.plugin.hook_data(() => {
          assert.equal(
            this.connection.transaction.notes.clamd_found_attachment,
            true,
          )
          resolve()
        }, this.connection)
      })
    })

    it('only_with_attachments, false', async () => {
      assert.equal(false, this.plugin.cfg.main.only_with_attachments)
      await new Promise((resolve) => {
        this.plugin.hook_data(() => {
          assert.equal(false, this.connection.transaction.parse_body)
          resolve()
        }, this.connection)
      })
    })

    it('only_with_attachments, true', async () => {
      this.plugin.cfg.main.only_with_attachments = true
      this.connection.transaction.attachment_hooks = () => {}
      await new Promise((resolve) => {
        this.plugin.hook_data(() => {
          assert.equal(true, this.plugin.cfg.main.only_with_attachments)
          assert.equal(true, this.connection.transaction.parse_body)
          resolve()
        }, this.connection)
      })
    })
  })

  describe('hook_data_post', () => {
    beforeEach(_set_up)

    it('skip attachment', async () => {
      this.connection.transaction.notes = { clamd_found_attachment: false }
      this.plugin.cfg.main.only_with_attachments = true
      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length > 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('skip authenticated', async () => {
      this.connection.notes.auth_user = 'user'
      this.plugin.cfg.check.authenticated = false
      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length > 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('checks local IP', async () => {
      this.connection.remote.is_local = true
      this.plugin.cfg.check.local_ip = true
      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length === 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('skips local IP', async () => {
      this.connection.remote.is_local = true
      this.plugin.cfg.check.local_ip = false
      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length > 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('checks private IP', async () => {
      this.connection.remote.is_private = true
      this.plugin.cfg.check.private_ip = true
      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length === 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('skips private IP', async () => {
      this.connection.remote.is_private = true
      this.plugin.cfg.check.private_ip = false
      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length > 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('checks public ip', async () => {
      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length === 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('skip localhost if check.local_ip = false and check.private_ip = true', async () => {
      this.connection.remote.is_local = true
      this.connection.remote.is_private = true

      this.plugin.cfg.check.local_ip = false
      this.plugin.cfg.check.private_ip = true

      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length > 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('checks localhost if check.local_ip = true and check.private_ip = false', async () => {
      this.connection.remote.is_local = true
      this.connection.remote.is_private = true

      this.plugin.cfg.check.local_ip = true
      this.plugin.cfg.check.private_ip = false

      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length === 0,
          )
          resolve()
        }, this.connection)
      })
    })

    it('message too big', async () => {
      this.connection.transaction.data_bytes = 513
      this.plugin.cfg.main.max_size = 512

      await new Promise((resolve) => {
        this.plugin.hook_data_post(() => {
          assert.ok(
            this.connection.transaction.results.get('clamd').skip.length > 0,
          )
          resolve()
        }, this.connection)
      })
    })
  })

  describe('send_clamd_predata', () => {
    beforeEach(_set_up)

    it('writes the proper commands to clamd socket', async () => {
      await new Promise((resolve) => {
        const server = new net.createServer((socket) => {
          socket.on('data', (data) => {
            assert.ok(
              data.toString(),
              `zINSTREAM\0Received: from Haraka clamd plugin\r\n`,
            )
            // console.log(`${data.toString()}`)
          })
          socket.on('end', () => {
            resolve()
          })
        })

        server.listen(65535, () => {
          const client = new net.Socket()
          client.connect(65535, () => {
            this.plugin.send_clamd_predata(client, () => {
              client.end()
            })
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

    const startClamd = (reply, cb) => {
      server = net.createServer((s) => {
        s.on('data', () => {})
        s.on('end', () => s.end(reply))
      })
      server.listen(0, '127.0.0.1', () => cb(server.address().port))
    }

    const primeTxn = (done) => {
      this.plugin = new fixtures.plugin('clamd')
      this.plugin.register()
      this.connection = fixtures.connection.createConnection()
      this.connection.init_transaction()
      const txn = this.connection.transaction
      txn.message_stream.add_line('Subject: hi\r\n')
      txn.message_stream.add_line('\r\n')
      txn.message_stream.add_line('body\r\n')
      txn.message_stream.add_line_end(done)
    }

    afterEach((t, done) => {
      const s = server
      server = null
      if (s && s.listening) return s.close(done)
      done()
    })

    const run = (reply, tweak) =>
      new Promise((resolve) =>
        primeTxn(() =>
          startClamd(reply, (port) => {
            this.plugin.cfg.main.clamd_socket = `127.0.0.1:${port}`
            tweak?.(this.plugin)
            this.plugin.hook_data_post((...a) => resolve(a), this.connection)
          }),
        ),
      )

    it('passes a clean message', async () => {
      const args = await run('stream: OK\n')
      assert.deepEqual(args, [])
      assert.ok(
        this.connection.transaction.results.get('clamd').pass.includes('clean'),
      )
    })

    it('DENYs an infected message', async () => {
      const [code, msg] = await run('stream: Eicar-Test-Signature FOUND\n')
      assert.equal(code, DENY)
      assert.match(msg, /infected with Eicar-Test-Signature/)
    })

    it('accepts a virus when reject.virus is false', async () => {
      const args = await run('stream: Eicar-Test FOUND\n', (p) => {
        p.cfg.reject.virus = false
      })
      assert.deepEqual(args, [])
      assert.ok(
        this.connection.transaction.results
          .get('clamd')
          .fail.includes('Eicar-Test'),
      )
    })

    it('continues past a clamd size-limit error', async () => {
      const args = await run('INSTREAM size limit exceeded\n')
      assert.deepEqual(args, [])
      assert.ok(
        this.connection.transaction.results
          .get('clamd')
          .err.join()
          .match(/size limit/),
      )
    })

    it('virus with reject-option disabled -> header + accept', async () => {
      // Phishing is disabled by default: matches allRE but not rejectRE
      const args = await run('stream: Heuristics.Phishing.Email FOUND\n')
      assert.deepEqual(args, [])
      assert.match(
        this.connection.transaction.header.get('X-Haraka-Virus'),
        /Heuristics\.Phishing\.Email/,
      )
    })

    it('connects over a unix domain socket', async () => {
      const sock = path.join(os.tmpdir(), `clamd-test-${process.pid}.sock`)
      const args = await new Promise((resolve) =>
        primeTxn(() => {
          server = net.createServer((s) => {
            s.on('data', () => {})
            s.on('end', () => s.end('stream: OK\n'))
          })
          server.listen(sock, () => {
            this.plugin.cfg.main.clamd_socket = sock
            this.plugin.hook_data_post((...a) => resolve(a), this.connection)
          })
        }),
      )
      assert.deepEqual(args, [])
    })

    it('skip_list_exclude match -> DENY', async () => {
      const [code] = await run('stream: Eicar-Test FOUND\n', (p) => {
        p.skip_list_exclude = [/Eicar/]
      })
      assert.equal(code, DENY)
    })

    it('skip_list match -> header + accept', async () => {
      const args = await run('stream: Eicar-Test FOUND\n', (p) => {
        p.skip_list = [/Eicar/]
      })
      assert.deepEqual(args, [])
      assert.match(
        this.connection.transaction.header.get('X-Haraka-Virus'),
        /Eicar-Test/,
      )
    })

    it('unknown clamd result -> DENYSOFT', async () => {
      const [code] = await run('mystery response\n', (p) => {
        p.cfg.reject.error = true
      })
      assert.equal(code, DENYSOFT)
    })

    it('honors randomize_host_order across a host list', async () => {
      const args = await new Promise((resolve) =>
        primeTxn(() =>
          startClamd('stream: OK\n', (port) => {
            this.plugin.cfg.main.clamd_socket = `127.0.0.1:${port} 127.0.0.1:${port}`
            this.plugin.cfg.main.randomize_host_order = true
            this.plugin.hook_data_post((...a) => resolve(a), this.connection)
          }),
        ),
      )
      assert.deepEqual(args, [])
    })

    it('skips relaying senders when check.relay=false', async () => {
      const args = await new Promise((resolve) =>
        primeTxn(() => {
          this.connection.relaying = true
          this.plugin.cfg.check.relay = false
          this.plugin.hook_data_post((...a) => resolve(a), this.connection)
        }),
      )
      assert.deepEqual(args, [])
      assert.ok(
        this.connection.transaction.results.get('clamd').skip.includes('relay'),
      )
    })

    it('connects to an IPv6 literal host', async () => {
      const args = await new Promise((resolve) =>
        primeTxn(() => {
          server = net.createServer((s) => {
            s.on('data', () => {})
            s.on('end', () => s.end('stream: OK\n'))
          })
          server.listen(0, '::1', () => {
            const { port } = server.address()
            this.plugin.cfg.main.clamd_socket = `[::1]:${port}`
            this.plugin.hook_data_post((...a) => resolve(a), this.connection)
          })
        }),
      )
      assert.deepEqual(args, [])
    })

    it('DENYSOFTs when no clamd host is reachable', async () => {
      const args = await new Promise((resolve) =>
        primeTxn(() => {
          this.plugin.cfg.main.clamd_socket = '127.0.0.1:1'
          this.plugin.cfg.reject.error = true
          this.plugin.hook_data_post((...a) => resolve(a), this.connection)
        }),
      )
      assert.equal(args[0], DENYSOFT)
    })
  })
})
