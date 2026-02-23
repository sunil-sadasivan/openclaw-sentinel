import { describe, it } from "node:test";
import assert from "node:assert/strict";

/**
 * Test the query safety checks that protect sentinel_query from
 * osqueryi meta-command injection and dangerous table access.
 */

const BLOCKED_TABLES = ["carves", "curl", "curl_certificate"];
const BLOCKED_PATTERNS = [
  /^\s*\./, // Any dot-command
  /;\s*\./, // Dot-command after semicolon
  /ATTACH\s/i, // ATTACH database
  /LOAD\s/i, // Load extension
];

function isBlocked(sql: string): string | null {
  const patternMatch = BLOCKED_PATTERNS.find((p) => p.test(sql));
  if (patternMatch) return "meta-command";
  const sqlLower = sql.toLowerCase();
  const tableMatch = BLOCKED_TABLES.find((t) => sqlLower.includes(t));
  if (tableMatch) return tableMatch;
  return null;
}

describe("sentinel_query safety checks", () => {
  describe("blocks osqueryi meta-commands", () => {
    it("blocks .shell command", () => {
      assert.ok(isBlocked(".shell ls -la /"));
    });

    it("blocks .shell with leading whitespace", () => {
      assert.ok(isBlocked("  .shell cat /etc/passwd"));
    });

    it("blocks .output (file exfiltration)", () => {
      assert.ok(isBlocked(".output /tmp/exfil.txt"));
    });

    it("blocks .read (file read)", () => {
      assert.ok(isBlocked(".read /etc/shadow"));
    });

    it("blocks .mode", () => {
      assert.ok(isBlocked(".mode csv"));
    });

    it("blocks .headers", () => {
      assert.ok(isBlocked(".headers on"));
    });

    it("blocks dot-command after semicolon", () => {
      assert.ok(isBlocked("SELECT 1; .shell whoami"));
    });

    it("blocks ATTACH database", () => {
      assert.ok(isBlocked("ATTACH '/tmp/evil.db' AS evil"));
    });

    it("blocks LOAD extension", () => {
      assert.ok(isBlocked("LOAD /tmp/evil.so"));
    });
  });

  describe("blocks dangerous tables", () => {
    it("blocks carves table", () => {
      assert.equal(isBlocked("SELECT * FROM carves"), "carves");
    });

    it("blocks curl table", () => {
      assert.equal(isBlocked("SELECT * FROM curl WHERE url='http://evil.com'"), "curl");
    });

    it("blocks curl_certificate table", () => {
      // "curl" substring matches first — both are blocked, exact match doesn't matter
      assert.ok(isBlocked("SELECT * FROM curl_certificate"));
    });

    it("blocks case-insensitive table names", () => {
      assert.equal(isBlocked("SELECT * FROM CURL"), "curl");
    });
  });

  describe("allows legitimate queries", () => {
    it("allows process listing", () => {
      assert.equal(isBlocked("SELECT * FROM processes"), null);
    });

    it("allows listening ports", () => {
      assert.equal(isBlocked("SELECT * FROM listening_ports WHERE port > 0"), null);
    });

    it("allows shell_history (contains 'shell' but not a meta-command)", () => {
      assert.equal(isBlocked("SELECT * FROM shell_history"), null);
    });

    it("allows logged_in_users", () => {
      assert.equal(isBlocked("SELECT * FROM logged_in_users"), null);
    });

    it("allows complex JOINs", () => {
      assert.equal(
        isBlocked(
          "SELECT p.name, lp.port FROM listening_ports lp JOIN processes p ON lp.pid = p.pid",
        ),
        null,
      );
    });
  });
});
