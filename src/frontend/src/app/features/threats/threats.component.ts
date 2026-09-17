import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ApiService } from '../../core/services/api.service';
import { ThreatDetection } from '../../core/models/types';

@Component({
  selector: 'app-threats',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <div class="space-y-6">
      <!-- Title Bar -->
      <div class="flex items-center justify-between pb-4 border-b border-[#27354f]">
        <div>
          <h1 class="text-xl font-bold text-white">Threat Detection Engine</h1>
          <p class="text-xs text-slate-400">Rule-based behavioral correlation & explainable risk scoring (0–100)</p>
        </div>

        <button (click)="loadThreats()" class="btn btn-secondary btn-sm flex items-center gap-1.5">
          <i class="las la-sync-alt" [ngClass]="{ 'animate-spin': loading() }"></i>
          <span>Refresh Detections</span>
        </button>
      </div>

      <!-- Threat Detections List -->
      <div class="space-y-4">
        @for (threat of threats(); track threat.id) {
          <div class="sec-card p-5 border-l-4 hover:border-l-[#38BDF8] transition"
               [ngClass]="{
                 'border-l-rose-500': threat.severityName === 'Critical',
                 'border-l-orange-500': threat.severityName === 'High',
                 'border-l-amber-400': threat.severityName === 'Medium',
                 'border-l-sky-400': threat.severityName === 'Low'
               }">
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-[#27354f]">
              <div class="flex items-center gap-3">
                <span class="badge" [ngClass]="getSeverityBadgeClass(threat.severityName)">
                  {{ threat.severityName }}
                </span>
                <span class="font-mono text-xs text-slate-400">Type: <span class="text-white font-semibold">{{ threat.threatTypeName }}</span></span>
                <span class="font-mono text-xs text-sky-400 font-bold">{{ threat.sourceIp }}</span>
              </div>

              <!-- Risk Score Meter -->
              <div class="flex items-center gap-3">
                <div class="text-right">
                  <div class="text-[10px] text-slate-500 uppercase font-mono">Explainable Risk</div>
                  <div class="text-sm font-black font-mono" [ngClass]="getRiskColor(threat.riskScore)">
                    {{ threat.riskScore }} / 100
                  </div>
                </div>
                <div class="w-16 bg-[#111827] rounded-full h-2 border border-[#27354f] overflow-hidden">
                  <div class="h-full rounded-full" [ngClass]="getRiskGaugeClass(threat.riskScore)" [style.width.%]="threat.riskScore"></div>
                </div>
              </div>
            </div>

            <!-- Threat Body -->
            <div class="py-3 space-y-2 text-xs">
              <div>
                <span class="text-slate-500 font-semibold">Rule Triggered:</span>
                <span class="text-slate-200 ml-1 font-medium">{{ threat.ruleName }}</span>
              </div>

              <div>
                <span class="text-slate-500 font-semibold">Detection Reason:</span>
                <p class="text-slate-300 mt-0.5 bg-[#111827] p-2.5 rounded-lg border border-[#27354f] font-sans">
                  {{ threat.detectionReason }}
                </p>
              </div>

              <div>
                <span class="text-slate-500 font-semibold">Recommended SOC Investigation Steps:</span>
                <pre class="text-[11px] text-slate-300 mt-0.5 bg-[#0e1422] p-2.5 rounded-lg border border-[#27354f] font-mono whitespace-pre-wrap">{{ threat.recommendedActions }}</pre>
              </div>
            </div>

            <!-- Footer with Incident status -->
            <div class="pt-3 border-t border-[#27354f] flex items-center justify-between text-xs">
              <div class="flex items-center gap-2 text-slate-400">
                <i class="las la-clock"></i>
                <span>Detected at: {{ threat.detectedAtUtc | date:'yyyy-MM-dd HH:mm:ss' }} UTC</span>
              </div>

              <div class="flex items-center gap-2">
                @if (threat.incidentCreated && threat.incidentId) {
                  <a [routerLink]="['/incidents']" class="btn btn-primary btn-sm text-[11px]">
                    <i class="las la-external-link-alt"></i>
                    <span>View Correlated Incident</span>
                  </a>
                } @else {
                  <span class="badge badge-low text-[10px]">Telemetry Logged</span>
                }
              </div>
            </div>
          </div>
        }

        @if (threats().length === 0) {
          <div class="sec-card text-center py-12 text-slate-500 text-xs">
            No behavioral threats currently detected by the correlation engine.
          </div>
        }
      </div>
    </div>
  `
})
export class ThreatsComponent implements OnInit {
  threats = signal<ThreatDetection[]>([]);
  loading = signal(false);

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.loadThreats();
  }

  loadThreats(): void {
    this.loading.set(true);
    this.api.getThreats({ pageSize: 30 }).subscribe({
      next: (res) => {
        this.loading.set(false);
        if (res.success && res.data) {
          this.threats.set(res.data.items);
        }
      },
      error: () => this.loading.set(false)
    });
  }

  getSeverityBadgeClass(sev: string): string {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      default: return 'badge-low';
    }
  }

  getRiskColor(score: number): string {
    if (score >= 80) return 'text-rose-500';
    if (score >= 60) return 'text-orange-400';
    if (score >= 30) return 'text-amber-400';
    return 'text-sky-400';
  }

  getRiskGaugeClass(score: number): string {
    if (score >= 80) return 'bg-rose-500';
    if (score >= 60) return 'bg-orange-500';
    if (score >= 30) return 'bg-amber-400';
    return 'bg-sky-400';
  }
}

