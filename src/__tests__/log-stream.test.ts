import { describe, it } from "node:test";
import assert from "node:assert/strict";

// We can't easily test the spawned process, but we can test the parsing logic
// by importing and testing the module's parse functions.
// Since parse functions are not exported, we test via the public class behavior.

// Instead, test the SSH event patterns that the parser handles:
describe("SSH log line patterns", () => {
  // These patterns match what sshd outputs and our parser expects

  it("matches 'Accepted publickey' pattern", () => {
    const line =
      '2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Accepted publickey for sunil from 100.79.207.74 port 52341 ssh2';
    const match = line.match(
      /sshd.*?:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
    );
    assert.ok(match);
    assert.equal(match[1], "publickey");
    assert.equal(match[2], "sunil");
    assert.equal(match[3], "100.79.207.74");
    assert.equal(match[4], "52341");
  });

  it("matches 'Accepted password' pattern", () => {
    const line =
      '2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Accepted password for root from 203.0.113.42 port 22 ssh2';
    const match = line.match(
      /sshd.*?:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
    );
    assert.ok(match);
    assert.equal(match[1], "password");
    assert.equal(match[2], "root");
    assert.equal(match[3], "203.0.113.42");
  });

  it("matches 'Failed password' pattern", () => {
    const line =
      '2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Failed password for sunil from 203.0.113.42 port 22 ssh2';
    const match = line.match(
      /sshd.*?:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
    );
    assert.ok(match);
    assert.equal(match[1], "sunil");
    assert.equal(match[2], "203.0.113.42");
  });

  it("matches 'Failed password for invalid user' pattern", () => {
    const line =
      '2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Failed password for invalid user admin from 203.0.113.42 port 22 ssh2';
    const match = line.match(
      /sshd.*?:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
    );
    assert.ok(match);
    assert.equal(match[1], "admin");
    assert.equal(match[2], "203.0.113.42");
  });

  it("matches 'Invalid user' pattern", () => {
    const line =
      '2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Invalid user admin from 203.0.113.42 port 22';
    const match = line.match(
      /sshd.*?:\s+Invalid\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
    );
    assert.ok(match);
    assert.equal(match[1], "admin");
    assert.equal(match[2], "203.0.113.42");
  });

  it("matches macOS sshd-session USER_PROCESS pattern", () => {
    const line =
      "Feb 22 16:39:32 sunils-mac-mini sshd-session: sunil [priv][58912]: USER_PROCESS: 58916 ttys001";
    const match = line.match(
      /sshd-session:\s+(\S+)\s+\[priv\]\[(\d+)\]:\s+USER_PROCESS:\s+(\d+)\s+(\S+)/,
    );
    assert.ok(match);
    assert.equal(match[1], "sunil");
    assert.equal(match[2], "58912");
    assert.equal(match[3], "58916");
    assert.equal(match[4], "ttys001");
  });

  it("does not match sshd-session DEAD_PROCESS", () => {
    const line =
      "Feb 22 16:38:12 sunils-mac-mini sshd-session: sunil [priv][53930]: DEAD_PROCESS: 53934 ttys012";
    const match = line.match(
      /sshd-session:\s+(\S+)\s+\[priv\]\[(\d+)\]:\s+USER_PROCESS:\s+(\d+)\s+(\S+)/,
    );
    assert.equal(match, null);
  });

  it("does not match unrelated sshd lines", () => {
    const line =
      '2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Connection closed by 100.79.207.74 port 52341';
    const accepted = line.match(/sshd.*?:\s+Accepted/);
    const failed = line.match(/sshd.*?:\s+Failed\s+password/);
    const invalid = line.match(/sshd.*?:\s+Invalid\s+user/);
    assert.equal(accepted, null);
    assert.equal(failed, null);
    assert.equal(invalid, null);
  });
});

describe("Tailscale IP detection", () => {
  function isTailscaleIP(host: string): boolean {
    const octets = host.split(".").map(Number);
    return octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127;
  }

  it("identifies Tailscale IPs", () => {
    assert.equal(isTailscaleIP("100.79.207.74"), true);
    assert.equal(isTailscaleIP("100.94.48.17"), true);
    assert.equal(isTailscaleIP("100.64.0.1"), true);
    assert.equal(isTailscaleIP("100.127.255.255"), true);
  });

  it("rejects non-Tailscale IPs", () => {
    assert.equal(isTailscaleIP("100.63.255.255"), false);
    assert.equal(isTailscaleIP("100.128.0.1"), false);
    assert.equal(isTailscaleIP("192.168.1.1"), false);
    assert.equal(isTailscaleIP("203.0.113.42"), false);
  });
});
