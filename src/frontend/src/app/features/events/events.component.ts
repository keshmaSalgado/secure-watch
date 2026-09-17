import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { SecurityEvent, PagedResult } from '../../core/models/types';

@Component({
  selector: 'app-events',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="space-y-6">
      <!-- Title & Search Filters Bar -->
      <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-[#27354f]">
        <div>
          <h1 class="text-xl font-bold text-white">Security Event Log</h1>
          <p class="text-xs text-slate-400">Search, filter, and inspect normalized enterprise telemetry</p>
        </div>

        <div class="flex items-center gap-2">
          <button (click)="loadEvents()" class="btn btn-secondary btn-sm flex items-center gap-1.5">
            <i class="las la-sync-alt" [ngClass]="{ 'animate-spin': loading() }"></i>
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <!-- Filters Row -->
      <div class="sec-card p-4 grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div>
          <label class="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Search Keywords</label>
          <input type="text" [(ngModel)]="searchTerm" (keyup.enter)="loadEvents()" placeholder="Search description, user, IP..."
                 class="form-input text-xs">
        </div>

        <div>
          <label class="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Category</label>
          <select [(ngModel)]="selectedCategory" (change)="loadEvents()" class="form-select text-xs">
            <option value="">All Categories</option>
            <option value="1">Successful Login</option>
            <option value="2">Failed Login</option>
            <option value="3">Password Change</option>
            <option value="4">Unauthorized Access</option>
            <option value="5">Suspicious API Request</option>
            <option value="6">Account Lockout</option>
            <option value="7">Privilege Escalation</option>
          </select>
        </div>

        <div>
          <label class="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Severity</label>
          <select [(ngModel)]="selectedSeverity" (change)="loadEvents()" class="form-select text-xs">
            <option value="">All Severities</option>
            <option value="1">Low</option>
            <option value="2">Medium</option>
            <option value="3">High</option>
            <option value="4">Critical</option>
          </select>
        </div>

        <div class="flex items-end">
          <button (click)="loadEvents()" class="btn btn-primary btn-sm w-full py-2">
            <i class="las la-filter"></i>
            <span>Apply Filters</span>
          </button>
        </div>
      </div>

      <!-- Table View -->
      <div class="sec-card p-0 overflow-hidden">
        <div class="overflow-x-auto">
          <table class="sec-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Username</th>
                <th>Device Telemetry</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              @for (ev of events(); track ev.id) {
                <tr>
                  <td class="font-mono text-xs text-slate-400 whitespace-nowrap">{{ ev.eventTimestampUtc | date:'yyyy-MM-dd HH:mm:ss' }}</td>
                  <td class="font-semibold text-white text-xs">{{ ev.eventType }}</td>
                  <td class="text-xs text-slate-300">{{ ev.categoryName }}</td>
                  <td>
                    <span class="badge" [ngClass]="getSeverityBadgeClass(ev.severityName)">{{ ev.severityName }}</span>
                  </td>
                  <td class="font-mono text-xs text-sky-400">{{ ev.sourceIp }}</td>
                  <td class="text-xs text-slate-300">{{ ev.username || '—' }}</td>
                  <td class="text-xs text-slate-400 truncate max-w-xs">{{ ev.deviceInfo || '—' }}</td>
                  <td>
                    <button (click)="selectedEvent.set(ev)" class="btn btn-secondary btn-sm text-[11px] py-1 px-2">
                      Inspect
                    </button>
                  </td>
                </tr>
              }
              @if (events().length === 0) {
                <tr>
                  <td colspan="8" class="text-center py-10 text-slate-500 text-xs">
                    No security events matching current criteria.
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>

        <!-- Pagination Controls -->
        <div class="p-4 border-t border-[#27354f] flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing Page <span class="font-mono text-white">{{ pageIndex() }}</span> of <span class="font-mono text-white">{{ totalPages() }}</span>
            ({{ totalCount() }} total events)
          </div>
          <div class="flex items-center gap-2">
            <button (click)="prevPage()" [disabled]="pageIndex() <= 1" class="btn btn-secondary btn-sm" [ngClass]="{ 'opacity-50 cursor-not-allowed': pageIndex() <= 1 }">
              Previous
            </button>
            <button (click)="nextPage()" [disabled]="pageIndex() >= totalPages()" class="btn btn-secondary btn-sm" [ngClass]="{ 'opacity-50 cursor-not-allowed': pageIndex() >= totalPages() }">
              Next
            </button>
          </div>
        </div>
      </div>

      <!-- Event Inspector Modal -->
      @if (selectedEvent()) {
        <div class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div class="bg-[#172033] border border-[#27354f] rounded-2xl w-full max-w-2xl p-6 shadow-2xl relative">
            <button (click)="selectedEvent.set(null)" class="absolute top-5 right-5 text-slate-400 hover:text-white">
              <i class="las la-times text-xl"></i>
            </button>

            <div class="flex items-center gap-3 mb-4">
              <span class="badge" [ngClass]="getSeverityBadgeClass(selectedEvent()!.severityName)">
                {{ selectedEvent()!.severityName }}
              </span>
              <h2 class="text-base font-bold text-white">{{ selectedEvent()!.eventType }}</h2>
            </div>

            <div class="space-y-3 text-xs">
              <div class="grid grid-cols-2 gap-3 p-3 rounded-xl bg-[#111827] border border-[#27354f]">
                <div><span class="text-slate-500">Event ID:</span> <span class="font-mono text-slate-300">{{ selectedEvent()!.id }}</span></div>
                <div><span class="text-slate-500">Timestamp:</span> <span class="font-mono text-slate-300">{{ selectedEvent()!.eventTimestampUtc | date:'yyyy-MM-dd HH:mm:ss' }} UTC</span></div>
                <div><span class="text-slate-500">Source IP:</span> <span class="font-mono text-sky-400">{{ selectedEvent()!.sourceIp }}</span></div>
                <div><span class="text-slate-500">Account:</span> <span class="font-semibold text-slate-300">{{ selectedEvent()!.username || 'N/A' }}</span></div>
              </div>

              <div>
                <label class="block font-semibold text-slate-400 mb-1">Description</label>
                <div class="p-3 rounded-lg bg-[#111827] border border-[#27354f] text-slate-200">
                  {{ selectedEvent()!.description }}
                </div>
              </div>

              <div>
                <label class="block font-semibold text-slate-400 mb-1">Client User Agent & Device</label>
                <div class="p-3 rounded-lg bg-[#111827] border border-[#27354f] font-mono text-[11px] text-slate-300 break-all">
                  {{ selectedEvent()!.userAgent || 'Not captured' }}
                </div>
              </div>
            </div>

            <div class="mt-6 pt-4 border-t border-[#27354f] text-right">
              <button (click)="selectedEvent.set(null)" class="btn btn-secondary btn-sm">Close</button>
            </div>
          </div>
        </div>
      }
    </div>
  `
})
export class EventsComponent implements OnInit {
  events = signal<SecurityEvent[]>([]);
  loading = signal(false);
  pageIndex = signal(1);
  pageSize = signal(20);
  totalCount = signal(0);
  totalPages = signal(1);

  searchTerm = '';
  selectedCategory = '';
  selectedSeverity = '';

  selectedEvent = signal<SecurityEvent | null>(null);

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.loadEvents();
  }

  loadEvents(): void {
    this.loading.set(true);

    const params: any = {
      pageIndex: this.pageIndex(),
      pageSize: this.pageSize(),
      searchTerm: this.searchTerm || undefined,
      category: this.selectedCategory ? parseInt(this.selectedCategory) : undefined,
      severity: this.selectedSeverity ? parseInt(this.selectedSeverity) : undefined
    };

    this.api.getEvents(params).subscribe({
      next: (res) => {
        this.loading.set(false);
        if (res.success && res.data) {
          this.events.set(res.data.items);
          this.totalCount.set(res.data.totalCount);
          this.totalPages.set(res.data.totalPages);
        }
      },
      error: () => this.loading.set(false)
    });
  }

  nextPage(): void {
    if (this.pageIndex() < this.totalPages()) {
      this.pageIndex.update(p => p + 1);
      this.loadEvents();
    }
  }

  prevPage(): void {
    if (this.pageIndex() > 1) {
      this.pageIndex.update(p => p - 1);
      this.loadEvents();
    }
  }

  getSeverityBadgeClass(sev: string): string {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      default: return 'badge-low';
    }
  }
}

