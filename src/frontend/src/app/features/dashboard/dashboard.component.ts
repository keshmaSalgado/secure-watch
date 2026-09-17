import { Component, OnInit, OnDestroy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { Subscription } from 'rxjs';
import { ApiService } from '../../core/services/api.service';
import { SignalRService } from '../../core/services/signalr.service';
import { DashboardOverview, ThreatTrend, SecurityEvent, Incident } from '../../core/models/types';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <div class="space-y-6">
      <!-- Top Title & Quick Refresh Banner -->
      <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-[#27354f]">
        <div>
          <h1 class="text-xl font-bold text-white flex items-center gap-2">
            <span>Security Operations Dashboard</span>
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
          </h1>
          <p class="text-xs text-slate-400">Enterprise SIEM Telemetry & Automated Threat Correlation</p>
        </div>

        <div class="flex items-center gap-2">
          <span class="text-xs text-slate-400 font-mono">Last refreshed: {{ lastRefreshed().toLocaleTimeString() }}</span>
          <button (click)="loadDashboard()" class="btn btn-secondary btn-sm flex items-center gap-1">
            <i class="las la-sync-alt" [ngClass]="{ 'animate-spin': loading() }"></i>
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <!-- Metric Cards Grid (6 Stat Counters) -->
      <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <!-- 1. Total Events -->
        <div class="sec-card p-4 relative overflow-hidden">
          <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400">Total Telemetry</div>
          <div class="text-2xl font-black text-white mt-1 font-mono">{{ overview()?.totalEvents ?? 0 }}</div>
          <div class="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <i class="las la-database text-xs text-[#38BDF8]"></i>
            <span>All ingested logs</span>
          </div>
        </div>

        <!-- 2. Detected Threats -->
        <div class="sec-card p-4 relative overflow-hidden">
          <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400">Threat Alerts</div>
          <div class="text-2xl font-black text-amber-400 mt-1 font-mono">{{ overview()?.totalThreatsDetected ?? 0 }}</div>
          <div class="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <i class="las la-crosshairs text-xs text-amber-400"></i>
            <span>Rule triggers</span>
          </div>
        </div>

        <!-- 3. Critical Incidents -->
        <div class="sec-card p-4 relative overflow-hidden">
          <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400">Critical Incidents</div>
          <div class="text-2xl font-black text-rose-500 mt-1 font-mono">{{ overview()?.criticalIncidents ?? 0 }}</div>
          <div class="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <i class="las la-skull-crossbones text-xs text-rose-500"></i>
            <span>P1 SOC escalations</span>
          </div>
        </div>

        <!-- 4. Active Incidents -->
        <div class="sec-card p-4 relative overflow-hidden">
          <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400">Active Incidents</div>
          <div class="text-2xl font-black text-indigo-400 mt-1 font-mono">{{ overview()?.activeIncidents ?? 0 }}</div>
          <div class="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <i class="las la-exclamation-circle text-xs text-indigo-400"></i>
            <span>In investigation</span>
          </div>
        </div>

        <!-- 5. Failed Logins -->
        <div class="sec-card p-4 relative overflow-hidden">
          <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400">Failed Logins</div>
          <div class="text-2xl font-black text-amber-400 mt-1 font-mono">{{ overview()?.failedLoginAttempts ?? 0 }}</div>
          <div class="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <i class="las la-user-lock text-xs text-amber-400"></i>
            <span>Password failures</span>
          </div>
        </div>

        <!-- 6. Suspicious IPs -->
        <div class="sec-card p-4 relative overflow-hidden">
          <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400">Suspicious IPs</div>
          <div class="text-2xl font-black text-sky-400 mt-1 font-mono">{{ overview()?.suspiciousIpCount ?? 0 }}</div>
          <div class="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
            <i class="las la-shield-virus text-xs text-sky-400"></i>
            <span>Hostile threat feeds</span>
          </div>
        </div>
      </div>

      <!-- Composite Risk Score & Threat Trend Graph Row -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Composite Risk Score Gauge Card -->
        <div class="sec-card flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-2">
              <h3 class="font-bold text-sm text-slate-200">Enterprise Security Risk Score</h3>
              <span class="badge" [ngClass]="getRiskBadgeClass(overview()?.overallRiskScore ?? 0)">
                {{ overview()?.overallRiskLevel ?? 'LOW' }} RISK
              </span>
            </div>
            <p class="text-xs text-slate-400">Explainable composite metric derived from incident severity and threat frequency.</p>
          </div>

          <div class="my-6 text-center">
            <div class="text-5xl font-black font-mono tracking-tight text-white mb-2">
              {{ overview()?.overallRiskScore ?? 0 }}<span class="text-xl text-slate-500">/100</span>
            </div>
            <!-- Visual Bar Gauge -->
            <div class="w-full bg-[#111827] rounded-full h-3 border border-[#27354f] overflow-hidden p-0.5">
              <div class="h-full rounded-full transition-all duration-500"
                   [style.width.%]="overview()?.overallRiskScore ?? 15"
                   [ngClass]="getRiskGaugeColor(overview()?.overallRiskScore ?? 0)"></div>
            </div>
          </div>

          <div class="grid grid-cols-4 gap-1 text-[11px] font-mono text-center pt-3 border-t border-[#27354f]">
            <div class="p-1 rounded bg-slate-800/40 text-sky-400">0-29<br><span class="text-[9px] text-slate-500">LOW</span></div>
            <div class="p-1 rounded bg-slate-800/40 text-amber-400">30-59<br><span class="text-[9px] text-slate-500">MED</span></div>
            <div class="p-1 rounded bg-slate-800/40 text-orange-400">60-79<br><span class="text-[9px] text-slate-500">HIGH</span></div>
            <div class="p-1 rounded bg-slate-800/40 text-rose-500">80-100<br><span class="text-[9px] text-slate-500">CRIT</span></div>
          </div>
        </div>

        <!-- 24-Hour Threat Activity Trend Graph (SVG Visualizer) -->
        <div class="sec-card lg:col-span-2 flex flex-col justify-between">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h3 class="font-bold text-sm text-slate-200">24-Hour Telemetry & Threat Volume</h3>
              <p class="text-xs text-slate-400">Hourly activity distribution across events and correlated detections</p>
            </div>
            <div class="flex items-center gap-3 text-xs">
              <span class="flex items-center gap-1.5 text-slate-400"><span class="w-2.5 h-2.5 rounded-full bg-[#38BDF8]"></span> Events</span>
              <span class="flex items-center gap-1.5 text-slate-400"><span class="w-2.5 h-2.5 rounded-full bg-[#F59E0B]"></span> Threats</span>
            </div>
          </div>

          <!-- Pure CSS/SVG Responsive Spark Histogram -->
          <div class="h-44 flex items-end gap-1.5 px-2 pt-4 pb-2 bg-[#111827] rounded-xl border border-[#27354f]">
            @for (trend of trends(); track $index) {
              <div class="flex-1 flex flex-col items-center gap-1 h-full justify-end group relative">
                <!-- Tooltip on hover -->
                <div class="absolute -top-12 bg-[#1e293b] border border-[#27354f] text-white text-[10px] px-2 py-1 rounded shadow-lg opacity-0 group-hover:opacity-100 transition pointer-events-none whitespace-nowrap z-20">
                  <div>{{ trend.timeLabel }}</div>
                  <div>Events: {{ trend.eventCount }} | Threats: {{ trend.threatCount }}</div>
                </div>

                <!-- Threat Bar -->
                <div class="w-full bg-amber-500/80 rounded-t transition-all"
                     [style.height.%]="getBarHeight(trend.threatCount, 15)"></div>
                <!-- Event Bar -->
                <div class="w-full bg-[#38BDF8] rounded-t transition-all"
                     [style.height.%]="getBarHeight(trend.eventCount, 50)"></div>

                <span class="text-[9px] font-mono text-slate-500 mt-1 transform -rotate-45 origin-top-left hidden sm:block">
                  {{ trend.timeLabel }}
                </span>
              </div>
            }
          </div>
        </div>
      </div>

      <!-- Live Recent Security Events & Active Incidents Queue -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Live Recent Events Table -->
        <div class="sec-card p-0 overflow-hidden">
          <div class="p-4 border-b border-[#27354f] flex items-center justify-between">
            <h3 class="font-bold text-sm text-slate-200 flex items-center gap-2">
              <i class="las la-stream text-[#38BDF8] text-base"></i>
              <span>Live Ingested Telemetry</span>
            </h3>
            <a routerLink="/events" class="text-xs text-[#38BDF8] hover:underline">View All &rarr;</a>
          </div>

          <div class="overflow-x-auto">
            <table class="sec-table">
              <thead>
                <tr>
                  <th>Event Type</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>User</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                @for (ev of recentEvents(); track ev.id) {
                  <tr>
                    <td class="font-semibold text-slate-200">{{ ev.eventType }}</td>
                    <td>
                      <span class="badge" [ngClass]="getSeverityBadgeClass(ev.severityName)">
                        {{ ev.severityName }}
                      </span>
                    </td>
                    <td class="font-mono text-xs text-sky-300">{{ ev.sourceIp }}</td>
                    <td class="text-xs text-slate-400">{{ ev.username || '—' }}</td>
                    <td class="font-mono text-[11px] text-slate-500">{{ ev.eventTimestampUtc | date:'HH:mm:ss' }}</td>
                  </tr>
                }
                @if (recentEvents().length === 0) {
                  <tr>
                    <td colspan="5" class="text-center py-6 text-slate-500 text-xs">No recent security events recorded.</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </div>

        <!-- Recent Active Incidents -->
        <div class="sec-card p-0 overflow-hidden">
          <div class="p-4 border-b border-[#27354f] flex items-center justify-between">
            <h3 class="font-bold text-sm text-slate-200 flex items-center gap-2">
              <i class="las la-exclamation-triangle text-rose-500 text-base"></i>
              <span>Active Security Incidents</span>
            </h3>
            <a routerLink="/incidents" class="text-xs text-[#38BDF8] hover:underline">Incident Queue &rarr;</a>
          </div>

          <div class="divide-y divide-[#27354f]">
            @for (inc of recentIncidents(); track inc.id) {
              <div class="p-4 hover:bg-[#111827]/60 transition flex items-start justify-between gap-4">
                <div class="space-y-1">
                  <div class="flex items-center gap-2">
                    <span class="font-mono font-bold text-xs text-[#38BDF8]">{{ inc.incidentCode }}</span>
                    <span class="badge" [ngClass]="getSeverityBadgeClass(inc.severityName)">{{ inc.severityName }}</span>
                    <span class="text-[10px] font-mono text-slate-400">Score: {{ inc.riskScore }}/100</span>
                  </div>
                  <h4 class="font-semibold text-sm text-white">{{ inc.title }}</h4>
                  <p class="text-xs text-slate-400 line-clamp-1">{{ inc.description }}</p>
                </div>
                <div class="text-right flex-shrink-0">
                  <span class="badge badge-medium text-[10px]">{{ inc.statusName }}</span>
                  <div class="text-[10px] text-slate-500 font-mono mt-1">{{ inc.createdAtUtc | date:'HH:mm' }}</div>
                </div>
              </div>
            }
            @if (recentIncidents().length === 0) {
              <div class="p-8 text-center text-slate-500 text-xs">
                No active security incidents at this time.
              </div>
            }
          </div>
        </div>
      </div>
    </div>
  `
})
export class DashboardComponent implements OnInit, OnDestroy {
  overview = signal<DashboardOverview | null>(null);
  trends = signal<ThreatTrend[]>([]);
  recentEvents = signal<SecurityEvent[]>([]);
  recentIncidents = signal<Incident[]>([]);
  loading = signal(false);
  lastRefreshed = signal(new Date());

  private subs = new Subscription();

  constructor(private api: ApiService, private signalr: SignalRService) {}

  ngOnInit(): void {
    this.loadDashboard();

    // Subscribe to live SignalR events
    this.subs.add(
      this.signalr.securityEvents$.subscribe(newEvent => {
        const events = [newEvent, ...this.recentEvents().slice(0, 7)];
        this.recentEvents.set(events);
      })
    );

    this.subs.add(
      this.signalr.incidentCreated$.subscribe(newInc => {
        const incidents = [newInc, ...this.recentIncidents().slice(0, 4)];
        this.recentIncidents.set(incidents);
      })
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  loadDashboard(): void {
    this.loading.set(true);

    this.api.getDashboardOverview().subscribe({
      next: (res) => {
        if (res.success && res.data) {
          this.overview.set(res.data);
          this.recentEvents.set(res.data.recentEvents);
          this.recentIncidents.set(res.data.recentIncidents);
        }
        this.loading.set(false);
        this.lastRefreshed.set(new Date());
      },
      error: () => this.loading.set(false)
    });

    this.api.getThreatTrends(12).subscribe({
      next: (res) => {
        if (res.success && res.data) {
          this.trends.set(res.data);
        }
      }
    });
  }

  getBarHeight(count: number, maxExpected: number): number {
    return Math.min(100, Math.max(10, Math.round((count / maxExpected) * 100)));
  }

  getRiskBadgeClass(score: number): string {
    if (score >= 80) return 'badge-critical';
    if (score >= 60) return 'badge-high';
    if (score >= 30) return 'badge-medium';
    return 'badge-low';
  }

  getRiskGaugeColor(score: number): string {
    if (score >= 80) return 'bg-rose-500';
    if (score >= 60) return 'bg-orange-500';
    if (score >= 30) return 'bg-amber-400';
    return 'bg-sky-400';
  }

  getSeverityBadgeClass(severity: string): string {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      default: return 'badge-low';
    }
  }
}

