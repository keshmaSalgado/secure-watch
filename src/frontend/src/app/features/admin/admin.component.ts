import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { UserItem, SecurityRuleItem, AuditLogItem } from '../../core/models/types';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="space-y-6">
      <!-- Title Bar -->
      <div class="flex items-center justify-between pb-4 border-b border-[#27354f]">
        <div>
          <h1 class="text-xl font-bold text-white flex items-center gap-2">
            <span>Governance & Administration</span>
            <span class="badge badge-critical text-[10px]">SuperAdmin Restricted</span>
          </h1>
          <p class="text-xs text-slate-400">User management, detection rule configuration, and immutable security audit logs</p>
        </div>

        <!-- Section Switcher -->
        <div class="flex items-center p-1 rounded-xl bg-[#111827] border border-[#27354f] text-xs">
          <button (click)="activeTab.set('users')" [ngClass]="{ 'bg-[#1e293b] text-[#38BDF8] shadow': activeTab() === 'users' }" class="px-3 py-1.5 rounded-lg text-slate-300 font-medium transition">
            <i class="las la-users mr-1"></i>Users
          </button>
          <button (click)="activeTab.set('rules')" [ngClass]="{ 'bg-[#1e293b] text-[#38BDF8] shadow': activeTab() === 'rules' }" class="px-3 py-1.5 rounded-lg text-slate-300 font-medium transition">
            <i class="las la-sliders-h mr-1"></i>Detection Rules
          </button>
          <button (click)="activeTab.set('audit')" [ngClass]="{ 'bg-[#1e293b] text-[#38BDF8] shadow': activeTab() === 'audit' }" class="px-3 py-1.5 rounded-lg text-slate-300 font-medium transition">
            <i class="las la-history mr-1"></i>Audit Trail
          </button>
        </div>
      </div>

      <!-- Tab 1: User Management -->
      @if (activeTab() === 'users') {
        <div class="space-y-4">
          <div class="flex justify-between items-center">
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">Platform Accounts (RBAC)</h3>
            <button (click)="showCreateUser.set(true)" class="btn btn-primary btn-sm flex items-center gap-1.5">
              <i class="las la-user-plus text-base"></i>
              <span>Create User</span>
            </button>
          </div>

          <div class="sec-card p-0 overflow-hidden">
            <table class="sec-table">
              <thead>
                <tr>
                  <th>Full Name</th>
                  <th>Email</th>
                  <th>Assigned Role</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                @for (u of users(); track u.id) {
                  <tr>
                    <td class="font-semibold text-white text-xs">{{ u.firstName }} {{ u.lastName }}</td>
                    <td class="font-mono text-xs text-sky-400">{{ u.email }}</td>
                    <td>
                      <span class="badge" [ngClass]="getRoleBadgeClass(u.role)">{{ u.role }}</span>
                    </td>
                    <td>
                      <span class="badge" [ngClass]="u.isActive ? 'badge-success' : 'badge-critical'">
                        {{ u.isActive ? 'Active' : 'Deactivated' }}
                      </span>
                    </td>
                    <td class="font-mono text-xs text-slate-400">{{ u.createdAtUtc | date:'yyyy-MM-dd' }}</td>
                    <td class="space-x-2">
                      <button (click)="toggleUserStatus(u)" class="btn btn-secondary btn-sm text-[10px] py-1 px-2">
                        {{ u.isActive ? 'Deactivate' : 'Activate' }}
                      </button>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </div>
      }

      <!-- Tab 2: Security Rules Management -->
      @if (activeTab() === 'rules') {
        <div class="space-y-4">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">Threat Detection Correlation Rules</h3>

          <div class="space-y-3">
            @for (rule of rules(); track rule.id) {
              <div class="sec-card p-5 space-y-3">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div class="flex items-center gap-2">
                    <span class="font-mono font-bold text-xs text-[#38BDF8]">{{ rule.code }}</span>
                    <span class="font-bold text-sm text-white">{{ rule.name }}</span>
                    <span class="badge" [ngClass]="rule.isEnabled ? 'badge-success' : 'badge-low'">
                      {{ rule.isEnabled ? 'ENABLED' : 'DISABLED' }}
                    </span>
                  </div>

                  <button (click)="toggleRuleEnabled(rule)" class="btn btn-secondary btn-sm text-xs">
                    {{ rule.isEnabled ? 'Disable Rule' : 'Enable Rule' }}
                  </button>
                </div>

                <p class="text-xs text-slate-400">{{ rule.description }}</p>

                <!-- Configurable Thresholds -->
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-[#27354f] text-xs">
                  <div>
                    <label class="block text-slate-500 uppercase text-[10px] font-mono mb-1">Threshold Count</label>
                    <input type="number" [(ngModel)]="rule.thresholdCount" (change)="saveRule(rule)" min="1" class="form-input text-xs font-mono">
                  </div>

                  <div>
                    <label class="block text-slate-500 uppercase text-[10px] font-mono mb-1">Time Window (Seconds)</label>
                    <input type="number" [(ngModel)]="rule.timeWindowSeconds" (change)="saveRule(rule)" min="5" step="5" class="form-input text-xs font-mono">
                  </div>

                  <div>
                    <label class="block text-slate-500 uppercase text-[10px] font-mono mb-1">Base Risk Score (0-100)</label>
                    <input type="number" [(ngModel)]="rule.baseRiskScore" (change)="saveRule(rule)" min="0" max="100" class="form-input text-xs font-mono">
                  </div>
                </div>
              </div>
            }
          </div>
        </div>
      }

      <!-- Tab 3: Immutable Audit Trail -->
      @if (activeTab() === 'audit') {
        <div class="space-y-4">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">Immutable Compliance Audit Logs</h3>

          <div class="sec-card p-0 overflow-hidden">
            <table class="sec-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Username</th>
                  <th>Action</th>
                  <th>Target Entity</th>
                  <th>Entity ID</th>
                  <th>Source IP</th>
                </tr>
              </thead>
              <tbody>
                @for (log of auditLogs(); track log.id) {
                  <tr>
                    <td class="font-mono text-xs text-slate-400 whitespace-nowrap">{{ log.timestampUtc | date:'yyyy-MM-dd HH:mm:ss' }}</td>
                    <td class="font-semibold text-white text-xs">{{ log.username }}</td>
                    <td>
                      <span class="badge badge-low text-[10px]">{{ log.action }}</span>
                    </td>
                    <td class="text-xs text-slate-300">{{ log.entityName }}</td>
                    <td class="font-mono text-[11px] text-slate-400 truncate max-w-xs">{{ log.entityId || '—' }}</td>
                    <td class="font-mono text-xs text-sky-400">{{ log.ipAddress || 'Internal' }}</td>
                  </tr>
                }
                @if (auditLogs().length === 0) {
                  <tr>
                    <td colspan="6" class="text-center py-10 text-slate-500 text-xs">No audit logs recorded yet.</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </div>
      }
    </div>
  `
})
export class AdminComponent implements OnInit {
  activeTab = signal<'users' | 'rules' | 'audit'>('users');
  users = signal<UserItem[]>([]);
  rules = signal<SecurityRuleItem[]>([]);
  auditLogs = signal<AuditLogItem[]>([]);
  showCreateUser = signal(false);

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.loadData();
  }

  loadData(): void {
    this.api.getUsers().subscribe(res => {
      if (res.success && res.data) this.users.set(res.data);
    });

    this.api.getRules().subscribe(res => {
      if (res.success && res.data) this.rules.set(res.data);
    });

    this.api.getAuditLogs().subscribe(res => {
      if (res.success && res.data) this.auditLogs.set(res.data.items);
    });
  }

  toggleUserStatus(user: UserItem): void {
    this.api.updateUserStatus(user.id, !user.isActive).subscribe({
      next: () => {
        user.isActive = !user.isActive;
      }
    });
  }

  toggleRuleEnabled(rule: SecurityRuleItem): void {
    rule.isEnabled = !rule.isEnabled;
    this.saveRule(rule);
  }

  saveRule(rule: SecurityRuleItem): void {
    this.api.updateRule(rule.id, {
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      timeWindowSeconds: rule.timeWindowSeconds,
      thresholdCount: rule.thresholdCount,
      isEnabled: rule.isEnabled,
      baseRiskScore: rule.baseRiskScore
    }).subscribe();
  }

  getRoleBadgeClass(role: string): string {
    switch (role) {
      case 'SuperAdmin': return 'badge-critical';
      case 'SecurityAdmin': return 'badge-high';
      case 'SecurityAnalyst': return 'badge-medium';
      default: return 'badge-low';
    }
  }
}

