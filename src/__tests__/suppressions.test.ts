import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SuppressionStore } from "../suppressions.js";
import type { SecurityEvent } from "../config.js";

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: "test-1",
    timestamp: Date.now(),
    severity: "high",
    category: "ssh_login",
    title: "SSH login from unknown host",
    description: 'User "root" logged in from unknown host: 203.0.113.42',
    details: { user: "root", host: "203.0.113.42", type: "publickey" },
    hostname: "test-host",
    ...overrides,
  };
}

describe("SuppressionStore", () => {
  let tmpDir: string;
  let store: SuppressionStore;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
    store = new SuppressionStore(tmpDir);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("starts with no rules", async () => {
    const rules = await store.list();
    assert.equal(rules.length, 0);
  });

  it("adds and lists rules", async () => {
    await store.add({
      scope: "title",
      title: "SSH login detected",
      reason: "Known Tailscale logins",
      expiresAt: null,
    });

    const rules = await store.list();
    assert.equal(rules.length, 1);
    assert.equal(rules[0].scope, "title");
    assert.equal(rules[0].title, "SSH login detected");
    assert.equal(rules[0].reason, "Known Tailscale logins");
    assert.equal(rules[0].suppressCount, 0);
  });

  it("suppresses by title", async () => {
    await store.add({
      scope: "title",
      title: "SSH login from unknown host",
      reason: "Expected",
      expiresAt: null,
    });

    const evt = makeEvent();
    const match = store.isSuppressed(evt);
    assert.ok(match);
    assert.equal(match!.reason, "Expected");
    assert.equal(match!.suppressCount, 1);
  });

  it("does not suppress non-matching title", async () => {
    await store.add({
      scope: "title",
      title: "sudo command executed",
      reason: "Normal",
      expiresAt: null,
    });

    const evt = makeEvent({ title: "SSH login from unknown host" });
    assert.equal(store.isSuppressed(evt), null);
  });

  it("suppresses by category", async () => {
    await store.add({
      scope: "category",
      category: "ssh_login",
      reason: "All SSH is fine",
      expiresAt: null,
    });

    const evt = makeEvent();
    const match = store.isSuppressed(evt);
    assert.ok(match);
  });

  it("suppresses by field match", async () => {
    await store.add({
      scope: "field",
      field: "user",
      fieldValue: "sunil",
      reason: "Sunil's own sudo",
      expiresAt: null,
    });

    const evt = makeEvent({
      title: "sudo command executed",
      category: "privilege",
      details: { user: "sunil", command: "/usr/bin/ls" },
    });
    assert.ok(store.isSuppressed(evt));

    // Different user should not be suppressed
    const evt2 = makeEvent({
      title: "sudo command executed",
      category: "privilege",
      details: { user: "attacker", command: "/bin/bash" },
    });
    assert.equal(store.isSuppressed(evt2), null);
  });

  it("suppresses by exact match", async () => {
    await store.add({
      scope: "exact",
      title: "SSH login from unknown host",
      description: 'User "root" logged in from unknown host: 203.0.113.42',
      reason: "Known scanner",
      expiresAt: null,
    });

    const evt = makeEvent();
    assert.ok(store.isSuppressed(evt));

    // Same title, different description should not match
    const evt2 = makeEvent({ description: "Different host" });
    assert.equal(store.isSuppressed(evt2), null);
  });

  it("respects expiry", async () => {
    await store.add({
      scope: "title",
      title: "SSH login from unknown host",
      reason: "Temporary",
      expiresAt: Date.now() - 1000, // Already expired
    });

    const evt = makeEvent();
    assert.equal(store.isSuppressed(evt), null);
  });

  it("removes rules", async () => {
    const rule = await store.add({
      scope: "title",
      title: "test",
      reason: "test",
      expiresAt: null,
    });

    assert.equal((await store.list()).length, 1);
    const removed = await store.remove(rule.id);
    assert.equal(removed, true);
    assert.equal((await store.list()).length, 0);
  });

  it("removes returns false for unknown id", async () => {
    const removed = await store.remove("nonexistent");
    assert.equal(removed, false);
  });

  it("cleans up expired rules", async () => {
    await store.add({
      scope: "title",
      title: "old",
      reason: "expired",
      expiresAt: Date.now() - 1000,
    });
    await store.add({
      scope: "title",
      title: "current",
      reason: "active",
      expiresAt: null,
    });

    const cleaned = await store.cleanup();
    assert.equal(cleaned, 1);
    const remaining = await store.list();
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].title, "current");
  });

  it("persists across instances", async () => {
    await store.add({
      scope: "title",
      title: "persisted",
      reason: "test persistence",
      expiresAt: null,
    });

    // New store instance pointing at same dir
    const store2 = new SuppressionStore(tmpDir);
    const rules = await store2.list();
    assert.equal(rules.length, 1);
    assert.equal(rules[0].title, "persisted");
  });

  it("describes rules in plain English", () => {
    assert.equal(
      SuppressionStore.describe({ scope: "title", title: "sudo command executed" } as any),
      'All alerts titled "sudo command executed"',
    );
    assert.equal(
      SuppressionStore.describe({ scope: "category", category: "ssh_login" } as any),
      'All alerts in category "ssh_login"',
    );
    assert.equal(
      SuppressionStore.describe({ scope: "field", field: "user", fieldValue: "sunil" } as any),
      'Alerts where user = "sunil"',
    );
    assert.equal(
      SuppressionStore.describe({ scope: "exact", title: "test" } as any),
      'Exact match: "test" with specific description',
    );
  });

  it("increments suppress count on repeated matches", async () => {
    await store.add({
      scope: "title",
      title: "SSH login from unknown host",
      reason: "Expected",
      expiresAt: null,
    });

    const evt = makeEvent();
    store.isSuppressed(evt);
    store.isSuppressed(evt);
    store.isSuppressed(evt);

    const rules = await store.list();
    assert.equal(rules[0].suppressCount, 3);
  });
});
