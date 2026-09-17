import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { IpReputation } from '../../core/models/types';

@Component({
  selector: 'app-intelligence',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="space-y-6">
      <!-- Title Bar -->
      <div class="pb-4 border-b border-[#27354f]">
        <h1 class="text-xl font-bold text-white">IP Threat Intelligence</h1>
        <p class="text-xs text-slate-400">Search reputation scores, ASN routing telemetry, Tor indicators, and associated security events</p>
      </div>

      <!-- IP Search Bar & Quick Seeds -->
      <div class="sec-card p-5 space-y-4">
        <form (ngSubmit)="searchIp()" class="flex flex-col sm:flex-row gap-3">
          <div class="relative flex-1">
            <i class="las la-globe absolute left-3 top-2.5 text-slate-400 text-lg"></i>
            <input type="text" [(ngModel)]="ipInput" name="ipInput" placeholder="Enter IPv4 or IPv6 address (e.g., 198.51.100.42)..."
                   class="form-input pl-10 font-mono text-sm">
          </div>
          <button type="submit" [disabled]="loading()" class="btn btn-primary text-xs px-6">
            @if (loading()) {
              <i class="las la-spinner animate-spin"></i>
            } @else {
              <i class="las la-search"></i>
            }
            <span>Investigate IP</span>
          </button>
        </form>

        <!-- Quick Demo Targets -->
        <div class="flex flex-wrap items-center gap-2 pt-2 text-xs">
          <span class="text-slate-500 font-mono text-[11px]">Quick Profiles:</span>
          <button (click)="quickInspect('198.51.100.42')" class="px-2 py-1 rounded bg-[#111827] border border-[#27354f] hover:border-rose-500/50 font-mono text-rose-400 text-[11px]">
            198.51.100.42 (Malicious Botnet)
          </button>
          <button (click)="quickInspect('185.220.101.5')" class="px-2 py-1 rounded bg-[#111827] border border-[#27354f] hover:border-amber-500/50 font-mono text-amber-400 text-[11px]">
            185.220.101.5 (Tor Exit Node)
          </button>
          <button (click)="quickInspect('203.0.113.88')" class="px-2 py-1 rounded bg-[#111827] border border-[#27354f] hover:border-indigo-500/50 font-mono text-indigo-400 text-[11px]">
            203.0.113.88 (VPN Transit)
          </button>
          <button (click)="quickInspect('10.0.0.15')" class="px-2 py-1 rounded bg-[#111827] border border-[#27354f] hover:border-emerald-500/50 font-mono text-emerald-400 text-[11px]">
            10.0.0.15 (HQ Trusted Subnet)
          </button>
        </div>
      </div>

      <!-- IP Profile Card -->
      @if (reputation()) {
        <div class="space-y-6">
          <div class="sec-card p-6 border-t-4"
               [ngClass]="reputation()!.isMalicious ? 'border-t-rose-500' : 'border-t-sky-400'">
            <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-[#27354f]">
              <div class="flex items-center gap-3">
                <div class="w-12 h-12 rounded-xl flex items-center justify-center font-bold text-xl"
                     [ngClass]="reputation()!.isMalicious ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-sky-500/20 text-sky-400 border border-sky-500/30'">
                  <i class="las" [ngClass]="reputation()!.isMalicious ? 'la-skull' : 'la-shield-alt'"></i>
                </div>
                <div>
                  <div class="flex items-center gap-2">
                    <h2 class="text-lg font-bold font-mono text-white">{{ reputation()!.ipAddress }}</h2>
                    @if (reputation()!.isMalicious) {
                      <span class="badge badge-critical">CONFIRMED HOSTILE</span>
                    } @else {
                      <span class="badge badge-low">STANDARD REPUTATION</span>
                    }
                  </div>
                  <div class="text-xs text-slate-400 mt-0.5">
                    {{ reputation()!.city || 'Unknown City' }}, {{ reputation()!.countryName || 'Unknown Country' }} ({{ reputation()!.countryCode }})
                  </div>
                </div>
              </div>

              <!-- Threat Score -->
              <div class="text-right">
                <div class="text-xs text-slate-400 uppercase font-mono">Reputation Score</div>
                <div class="text-3xl font-black font-mono mt-0.5"
                     [ngClass]="reputation()!.reputationScore >= 80 ? 'text-rose-500' : (reputation()!.reputationScore >= 50 ? 'text-amber-400' : 'text-sky-400')">
                  {{ reputation()!.reputationScore }} <span class="text-base text-slate-500">/ 100</span>
                </div>
              </div>
            </div>

            <!-- Detailed Telemetry Indicators -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 my-6 text-xs">
              <div class="p-3 rounded-xl bg-[#111827] border border-[#27354f]">
                <div class="text-slate-500 uppercase text-[10px] font-mono">ISP / Hosting Provider</div>
                <div class="font-semibold text-slate-200 mt-1 truncate">{{ reputation()!.isp || 'N/A' }}</div>
              </div>

              <div class="p-3 rounded-xl bg-[#111827] border border-[#27354f]">
                <div class="text-slate-500 uppercase text-[10px] font-mono">Autonomous System (ASN)</div>
                <div class="font-mono text-slate-200 mt-1">{{ reputation()!.asn || 'AS-UNKNOWN' }}</div>
              </div>

              <div class="p-3 rounded-xl bg-[#111827] border border-[#27354f]">
                <div class="text-slate-500 uppercase text-[10px] font-mono">Tor Node Indicator</div>
                <div class="font-semibold mt-1" [ngClass]="reputation()!.isTor ? 'text-rose-400' : 'text-slate-400'">
                  {{ reputation()!.isTor ? 'YES (Tor Exit Node)' : 'No' }}
                </div>
              </div>

              <div class="p-3 rounded-xl bg-[#111827] border border-[#27354f]">
                <div class="text-slate-500 uppercase text-[10px] font-mono">VPN / Proxy Relay</div>
                <div class="font-semibold mt-1" [ngClass]="reputation()!.isVpnOrProxy ? 'text-amber-400' : 'text-slate-400'">
                  {{ reputation()!.isVpnOrProxy ? 'YES (Anonymizer)' : 'No' }}
                </div>
              </div>
            </div>

            <!-- Historical Security Events Associated with this IP -->
            <div class="mt-6">
              <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono mb-3">
                Telemetry Associated with this IP ({{ reputation()!.recentEvents.length }} recent records)
              </h3>

              <div class="overflow-x-auto rounded-xl border border-[#27354f]">
                <table class="sec-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Event Type</th>
                      <th>Severity</th>
                      <th>Target Account</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    @for (ev of reputation()!.recentEvents; track ev.id) {
                      <tr>
                        <td class="font-mono text-xs text-slate-400 whitespace-nowrap">{{ ev.eventTimestampUtc | date:'HH:mm:ss' }}</td>
                        <td class="font-semibold text-white text-xs">{{ ev.eventType }}</td>
                        <td>
                          <span class="badge" [ngClass]="ev.severityName === 'Critical' ? 'badge-critical' : 'badge-high'">{{ ev.severityName }}</span>
                        </td>
                        <td class="text-xs text-slate-300">{{ ev.username || '—' }}</td>
                        <td class="text-xs text-slate-400 truncate max-w-sm">{{ ev.description }}</td>
                      </tr>
                    }
                    @if (reputation()!.recentEvents.length === 0) {
                      <tr>
                        <td colspan="5" class="text-center py-6 text-slate-500 text-xs">No local security events currently recorded for this IP address.</td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      }
    </div>
  `
})
export class IntelligenceComponent implements OnInit {
  ipInput = '198.51.100.42';
  reputation = signal<IpReputation | null>(null);
  loading = signal(false);

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.searchIp();
  }

  quickInspect(ip: string): void {
    this.ipInput = ip;
    this.searchIp();
  }

  searchIp(): void {
    if (!this.ipInput) return;
    this.loading.set(true);

    this.api.getIpReputation(this.ipInput.trim()).subscribe({
      next: (res) => {
        this.loading.set(false);
        if (res.success && res.data) {
          this.reputation.set(res.data);
        }
      },
      error: () => this.loading.set(false)
    });
  }
}

