import { Component, OnInit, OnDestroy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { SignalRService } from '../../core/services/signalr.service';
import { ApiService } from '../../core/services/api.service';
import { SecurityEvent } from '../../core/models/types';

@Component({
  selector: 'app-monitoring',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex items-center justify-between pb-4 border-b border-[#27354f]">
        <div>
          <h1 class="text-xl font-bold text-white flex items-center gap-2">
            <span>Live Security Monitoring Console</span>
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
          </h1>
          <p class="text-xs text-slate-400">Continuous telemetry event stream via WebSockets (SignalR Backplane)</p>
        </div>

        <div class="flex items-center gap-3">
          <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#172033] border border-[#27354f] text-xs">
            <span class="text-slate-400">Stream Status:</span>
            <span class="font-mono text-emerald-400 font-bold uppercase">{{ signalr.connectionStatus() }}</span>
          </div>
          <button (click)="clearStream()" class="btn btn-secondary btn-sm">Clear Buffer</button>
        </div>
      </div>

      <!-- Live Stream Stats -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="sec-card p-4">
          <div class="text-[11px] font-bold text-slate-400 uppercase">Buffer Count</div>
          <div class="text-2xl font-black text-white font-mono mt-1">{{ streamEvents().length }}</div>
        </div>
        <div class="sec-card p-4">
          <div class="text-[11px] font-bold text-slate-400 uppercase">High/Critical Events</div>
          <div class="text-2xl font-black text-rose-500 font-mono mt-1">{{ countCritical() }}</div>
        </div>
        <div class="sec-card p-4">
          <div class="text-[11px] font-bold text-slate-400 uppercase">Unique Source IPs</div>
          <div class="text-2xl font-black text-[#38BDF8] font-mono mt-1">{{ countUniqueIps() }}</div>
        </div>
        <div class="sec-card p-4">
          <div class="text-[11px] font-bold text-slate-400 uppercase">Protocol Mode</div>
          <div class="text-2xl font-black text-indigo-400 font-mono mt-1">WSS / JSON</div>
        </div>
      </div>

      <!-- Event Stream Terminal / Table -->
      <div class="sec-card p-0 overflow-hidden">
        <div class="p-3 bg-[#111827] border-b border-[#27354f] flex items-center justify-between text-xs text-slate-400">
          <span class="font-mono uppercase tracking-wider text-[11px]">Active Ingress Stream</span>
          <span class="text-slate-500 text-[11px]">Real-time updates arrive without page refresh</span>
        </div>

        <div class="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table class="sec-table">
            <thead class="sticky top-0 z-10">
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Source IP</th>
                <th>Target User</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              @for (ev of streamEvents(); track ev.id) {
                <tr class="transition hover:bg-[#1e293b]/50">
                  <td class="font-mono text-xs text-slate-400 whitespace-nowrap">{{ ev.eventTimestampUtc | date:'HH:mm:ss.SSS' }}</td>
                  <td class="font-semibold text-white text-xs">{{ ev.eventType }}</td>
                  <td>
                    <span class="badge" [ngClass]="getSeverityBadgeClass(ev.severityName)">
                      {{ ev.severityName }}
                    </span>
                  </td>
                  <td class="text-xs text-slate-300">{{ ev.categoryName }}</td>
                  <td class="font-mono text-xs text-sky-300">{{ ev.sourceIp }}</td>
                  <td class="text-xs text-slate-400">{{ ev.username || '—' }}</td>
                  <td class="text-xs text-slate-300 max-w-xs truncate">{{ ev.description }}</td>
                </tr>
              }
              @if (streamEvents().length === 0) {
                <tr>
                  <td colspan="7" class="text-center py-12 text-slate-500 text-xs">
                    Listening for incoming security telemetry events...
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `
})
export class MonitoringComponent implements OnInit, OnDestroy {
  streamEvents = signal<SecurityEvent[]>([]);
  private sub = new Subscription();

  constructor(public signalr: SignalRService, private api: ApiService) {}

  ngOnInit(): void {
    // Initial fetch of recent 20 events
    this.api.getEvents({ pageSize: 20 }).subscribe({
      next: (res) => {
        if (res.success && res.data) {
          this.streamEvents.set(res.data.items);
        }
      }
    });

    // Real-time listener
    this.sub = this.signalr.securityEvents$.subscribe(newEvent => {
      this.streamEvents.set([newEvent, ...this.streamEvents().slice(0, 49)]);
    });
  }

  ngOnDestroy(): void {
    this.sub.unsubscribe();
  }

  clearStream(): void {
    this.streamEvents.set([]);
  }

  countCritical(): number {
    return this.streamEvents().filter(e => e.severityName === 'Critical' || e.severityName === 'High').length;
  }

  countUniqueIps(): number {
    return new Set(this.streamEvents().map(e => e.sourceIp)).size;
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

