/**
 * Alert suppression — allows users to acknowledge and silence recurring alerts.
 *
 * Suppressions match against SecurityEvent fields using configurable scope:
 * - "exact": matches title + description exactly
 * - "title": matches events with the same title
 * - "category": matches all events in a category (e.g., all ssh_login)
 * - "field": matches a specific field value (e.g., details.user === "alice")
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import type { SecurityEvent } from "./config.js";

export interface SuppressionRule {
  id: string;
  /** What to match on */
  scope: "exact" | "title" | "category" | "field";
  /** For scope=title: the event title to match */
  title?: string;
  /** For scope=category: the category to match */
  category?: string;
  /** For scope=exact: title + description must match */
  description?: string;
  /** For scope=field: match a specific detail field */
  field?: string;
  fieldValue?: string;
  /** Human-readable reason for suppression */
  reason: string;
  /** When this suppression was created */
  createdAt: number;
  /** Optional expiry (epoch ms). null = permanent */
  expiresAt: number | null;
  /** How many times this rule has suppressed an alert */
  suppressCount: number;
  /** Last time this rule suppressed an alert */
  lastSuppressedAt: number | null;
}

export class SuppressionStore {
  private filePath: string;
  private rules: SuppressionRule[] = [];
  private loaded = false;

  constructor(sentinelDir: string) {
    this.filePath = join(sentinelDir, "suppressions.json");
  }

  async load(): Promise<void> {
    if (this.loaded) return;
    if (!existsSync(this.filePath)) {
      this.rules = [];
      this.loaded = true;
      return;
    }
    try {
      const content = await readFile(this.filePath, "utf-8");
      this.rules = JSON.parse(content);
      this.loaded = true;
    } catch {
      this.rules = [];
      this.loaded = true;
    }
  }

  private async save(): Promise<void> {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true });
    }
    await writeFile(this.filePath, JSON.stringify(this.rules, null, 2));
  }

  /**
   * Check if an event is suppressed by any active rule.
   * Returns the matching rule, or null if not suppressed.
   */
  isSuppressed(evt: SecurityEvent): SuppressionRule | null {
    const now = Date.now();

    for (const rule of this.rules) {
      // Check expiry
      if (rule.expiresAt !== null && rule.expiresAt < now) continue;

      let matches = false;

      switch (rule.scope) {
        case "exact":
          matches = evt.title === rule.title && evt.description === rule.description;
          break;
        case "title":
          matches = evt.title === rule.title;
          break;
        case "category":
          matches = evt.category === rule.category;
          break;
        case "field":
          if (rule.field && typeof evt.details === "object" && evt.details !== null) {
            const details = evt.details as Record<string, unknown>;
            matches = String(details[rule.field]) === rule.fieldValue;
          }
          break;
      }

      if (matches) {
        // Update stats (fire-and-forget save)
        rule.suppressCount++;
        rule.lastSuppressedAt = now;
        this.save().catch(() => {});
        return rule;
      }
    }

    return null;
  }

  /**
   * Add a new suppression rule.
   */
  async add(rule: Omit<SuppressionRule, "id" | "createdAt" | "suppressCount" | "lastSuppressedAt">): Promise<SuppressionRule> {
    await this.load();

    const newRule: SuppressionRule = {
      ...rule,
      id: `sup-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      createdAt: Date.now(),
      suppressCount: 0,
      lastSuppressedAt: null,
    };

    this.rules.push(newRule);
    await this.save();
    return newRule;
  }

  /**
   * Remove a suppression rule by ID.
   */
  async remove(id: string): Promise<boolean> {
    await this.load();
    const before = this.rules.length;
    this.rules = this.rules.filter((r) => r.id !== id);
    if (this.rules.length < before) {
      await this.save();
      return true;
    }
    return false;
  }

  /**
   * List all active suppression rules.
   */
  async list(): Promise<SuppressionRule[]> {
    await this.load();
    const now = Date.now();
    // Return all, but mark expired ones
    return this.rules.map((r) => ({
      ...r,
      _expired: r.expiresAt !== null && r.expiresAt < now,
    })) as SuppressionRule[];
  }

  /**
   * Clean up expired rules.
   */
  async cleanup(): Promise<number> {
    await this.load();
    const now = Date.now();
    const before = this.rules.length;
    this.rules = this.rules.filter((r) => r.expiresAt === null || r.expiresAt >= now);
    if (this.rules.length < before) {
      await this.save();
    }
    return before - this.rules.length;
  }

  /**
   * Describe what a rule matches in plain English.
   */
  static describe(rule: SuppressionRule): string {
    switch (rule.scope) {
      case "exact":
        return `Exact match: "${rule.title}" with specific description`;
      case "title":
        return `All alerts titled "${rule.title}"`;
      case "category":
        return `All alerts in category "${rule.category}"`;
      case "field":
        return `Alerts where ${rule.field} = "${rule.fieldValue}"`;
      default:
        return `Unknown scope: ${rule.scope}`;
    }
  }
}
