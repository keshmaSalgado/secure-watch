import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { Incident, AiIncidentAnalysis } from '../../core/models/types';

@Component({
  selector: 'app-incidents',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="space-y-6">
      <!-- Title Bar -->
      <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-[#27354f]">
        <div>
          <h1 class="text-xl font-bold text-white">Security Incident Queue</h1>
          <p class="text-xs text-slate-400">SOC Investigation Workspace, Event Correlation, and Lifecycle Triaging</p>
        </div>

        <button (click)="loadIncidents()" class="btn btn-secondary btn-sm flex items-center gap-1.5">
          <i class="las la-sync-alt" [ngClass]="{ 'animate-spin': loading() }"></i>
          <span>Refresh Incidents</span>
        </button>
      </div>

      <!-- Filters & Queue Table -->
      <div class="sec-card p-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div>
          <label class="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Status Filter</label>
          <select [(ngModel)]="statusFilter" (change)="loadIncidents()" class="form-select text-xs">
            <option value="">All Statuses</option>
            <option value="1">Open</option>
            <option value="2">Investigating</option>
            <option value="3">Escalated</option>
            <option value="4">Resolved</option>
            <option value="5">Closed</option>
          </select>
        </div>

        <div>
          <label class="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Severity Filter</label>
          <select [(ngModel)]="severityFilter" (change)="loadIncidents()" class="form-select text-xs">
            <option value="">All Severities</option>
            <option value="1">Low</option>
            <option value="2">Medium</option>
            <option value="3">High</option>
            <option value="4">Critical</option>
          </select>
        </div>

        <div>
          <label class="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Search Incidents</label>
          <input type="text" [(ngModel)]="searchTerm" (keyup.enter)="loadIncidents()" placeholder="Code, title, IP..." class="form-input text-xs">
        </div>
      </div>

      <!-- Incidents Table -->
      <div class="sec-card p-0 overflow-hidden">
        <div class="overflow-x-auto">
          <table class="sec-table">
            <thead>
              <tr>
                <th>Code</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Status</th>
                <th>Source IP</th>
                <th>Assigned Analyst</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              @for (inc of incidents(); track inc.id) {
                <tr class="hover:bg-[#1e293b]/50 transition cursor-pointer" (click)="openIncident(inc)">
                  <td class="font-mono font-bold text-xs text-[#38BDF8]">{{ inc.incidentCode }}</td>
                  <td class="font-semibold text-white text-xs max-w-xs truncate">{{ inc.title }}</td>
                  <td>
                    <span class="badge" [ngClass]="getSeverityBadgeClass(inc.severityName)">{{ inc.severityName }}</span>
                  </td>
                  <td class="font-mono font-bold text-xs" [ngClass]="getRiskColor(inc.riskScore)">{{ inc.riskScore }} / 100</td>
                  <td>
                    <span class="badge" [ngClass]="getStatusBadgeClass(inc.statusName)">{{ inc.statusName }}</span>
                  </td>
                  <td class="font-mono text-xs text-slate-300">{{ inc.sourceIp || '—' }}</td>
                  <td class="text-xs text-slate-300">{{ inc.assignedAnalystName || 'Unassigned' }}</td>
                  <td>
                    <button class="btn btn-primary btn-sm text-[11px] py-1 px-2.5">
                      Open Workspace
                    </button>
                  </td>
                </tr>
              }
              @if (incidents().length === 0) {
                <tr>
                  <td colspan="8" class="text-center py-12 text-slate-500 text-xs">No incidents match the active filters.</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>

      <!-- Incident Workspace Drawer / Modal -->
      @if (activeIncident()) {
        <div class="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div class="bg-[#172033] border border-[#27354f] rounded-2xl w-full max-w-4xl p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <button (click)="activeIncident.set(null)" class="absolute top-5 right-5 text-slate-400 hover:text-white">
              <i class="las la-times text-2xl"></i>
            </button>

            <!-- Incident Workspace Header -->
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-[#27354f]">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="font-mono font-black text-sm text-[#38BDF8]">{{ activeIncident()!.incidentCode }}</span>
                  <span class="badge" [ngClass]="getSeverityBadgeClass(activeIncident()!.severityName)">{{ activeIncident()!.severityName }}</span>
                  <span class="badge" [ngClass]="getStatusBadgeClass(activeIncident()!.statusName)">{{ activeIncident()!.statusName }}</span>
                </div>
                <h2 class="text-lg font-bold text-white">{{ activeIncident()!.title }}</h2>
              </div>

              <!-- AI Analysis Trigger Button -->
              <button (click)="runAiAnalysis()" [disabled]="aiLoading()" class="btn btn-secondary btn-sm border-indigo-500/50 text-indigo-300 hover:bg-indigo-500/10 flex items-center gap-1.5">
                <i class="las la-brain text-indigo-400 text-base" [ngClass]="{ 'animate-pulse': aiLoading() }"></i>
                <span>{{ aiLoading() ? 'Analyzing with AI...' : 'AI Attack Synthesis' }}</span>
              </button>
            </div>

            <!-- AI Synthesis Alert (if generated) -->
            @if (aiAnalysis()) {
              <div class="my-4 p-4 rounded-xl bg-indigo-950/40 border border-indigo-500/40 text-xs space-y-2">
                <div class="flex items-center justify-between text-indigo-300 font-bold uppercase tracking-wider text-[11px]">
                  <span>AI Copilot Threat Synthesis</span>
                  <span class="font-mono">Category: {{ aiAnalysis()!.attackCategory }}</span>
                </div>
                <p class="text-slate-200 leading-relaxed">{{ aiAnalysis()!.summary }}</p>
                <div>
                  <span class="font-semibold text-indigo-300">Potential Attack Impact:</span>
                  <p class="text-slate-300">{{ aiAnalysis()!.potentialImpact }}</p>
                </div>
                <div class="pt-2 border-t border-indigo-500/20">
                  <span class="font-semibold text-indigo-300">AI Recommendations:</span>
                  <ul class="list-disc list-inside text-slate-300 mt-1 space-y-1">
                    @for (rec of aiAnalysis()!.recommendations; track $index) {
                      <li>{{ rec }}</li>
                    }
                  </ul>
                </div>
              </div>
            }

            <!-- Incident Workspace Body -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 my-6 text-xs">
              <!-- Left Column: Details & Investigation Actions -->
              <div class="space-y-4">
                <div class="p-3.5 rounded-xl bg-[#111827] border border-[#27354f] space-y-2">
                  <div class="text-slate-400 uppercase font-mono text-[10px] font-bold">Metadata</div>
                  <div><span class="text-slate-500">Source IP:</span> <span class="font-mono text-sky-400 font-semibold">{{ activeIncident()!.sourceIp || 'Internal' }}</span></div>
                  <div><span class="text-slate-500">Risk Score:</span> <span class="font-mono font-bold" [ngClass]="getRiskColor(activeIncident()!.riskScore)">{{ activeIncident()!.riskScore }}/100</span></div>
                  <div><span class="text-slate-500">Assigned To:</span> <span class="text-slate-200 font-semibold">{{ activeIncident()!.assignedAnalystName || 'Unassigned' }}</span></div>
                  <div><span class="text-slate-500">Created:</span> <span class="font-mono text-slate-400">{{ activeIncident()!.createdAtUtc | date:'yyyy-MM-dd HH:mm' }} UTC</span></div>
                </div>

                <!-- Assignment Control -->
                <div class="p-3.5 rounded-xl bg-[#111827] border border-[#27354f] space-y-2">
                  <label class="block text-slate-400 uppercase font-mono text-[10px] font-bold">Assign Analyst</label>
                  <select [(ngModel)]="selectedAnalystId" (change)="assignAnalyst()" class="form-select text-xs">
                    <option value="analyst@securewatch.local">Alex Rivera (SOC Lead)</option>
                    <option value="secadmin@securewatch.local">Sarah Connor (SecOps)</option>
                    <option value="admin@securewatch.local">John Vance (CISO)</option>
                  </select>
                </div>

                <!-- Resolution Control -->
                @if (activeIncident()!.statusName !== 'Resolved') {
                  <div class="p-3.5 rounded-xl bg-[#111827] border border-[#27354f] space-y-2">
                    <label class="block text-slate-400 uppercase font-mono text-[10px] font-bold">Close / Resolve Incident</label>
                    <textarea [(ngModel)]="resolutionSummary" placeholder="Explain root cause and actions taken..." rows="3" class="form-input text-xs"></textarea>
                    <button (click)="resolveIncident()" class="btn btn-primary btn-sm w-full py-2">
                      <i class="las la-check-circle"></i>
                      <span>Resolve Incident</span>
                    </button>
                  </div>
                } @else {
                  <div class="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs">
                    <div class="font-bold mb-1">Resolved on {{ activeIncident()!.resolvedAtUtc | date:'yyyy-MM-dd HH:mm' }}</div>
                    <p class="text-slate-300">{{ activeIncident()!.resolutionSummary }}</p>
                  </div>
                }
              </div>

              <!-- Right 2 Columns: Timeline Notes & Evidence Events -->
              <div class="md:col-span-2 space-y-5">
                <!-- Notes Timeline -->
                <div class="sec-card p-4">
                  <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono mb-3">Investigation Timeline Notes</h3>

                  <div class="space-y-3 max-h-56 overflow-y-auto mb-4">
                    @for (note of activeIncident()!.notes; track note.id) {
                      <div class="p-3 rounded-lg bg-[#111827] border border-[#27354f]">
                        <div class="flex items-center justify-between text-slate-400 text-[11px] mb-1">
                          <span class="font-semibold text-[#38BDF8]">{{ note.authorName }}</span>
                          <span class="font-mono text-slate-500">{{ note.createdAtUtc | date:'HH:mm:ss' }}</span>
                        </div>
                        <p class="text-slate-200">{{ note.noteText }}</p>
                      </div>
                    }
                    @if (!activeIncident()!.notes?.length) {
                      <div class="text-center py-4 text-slate-500 text-xs">No investigation notes entered yet.</div>
                    }
                  </div>

                  <!-- Add note box -->
                  <div class="flex gap-2">
                    <input type="text" [(ngModel)]="newNoteText" (keyup.enter)="addNote()" placeholder="Add investigation note..."
                           class="form-input text-xs flex-1">
                    <button (click)="addNote()" class="btn btn-secondary btn-sm px-4">
                      <span>Post Note</span>
                    </button>
                  </div>
                </div>

                <!-- Correlated Telemetry Events -->
                <div class="sec-card p-4">
                  <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono mb-2">Correlated Telemetry Evidence ({{ activeIncident()!.linkedEvents?.length ?? 0 }} Events)</h3>
                  <div class="overflow-x-auto max-h-48 overflow-y-auto rounded-lg border border-[#27354f]">
                    <table class="sec-table text-[11px]">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Event</th>
                          <th>IP</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        @for (ev of activeIncident()!.linkedEvents; track ev.id) {
                          <tr>
                            <td class="font-mono text-slate-400">{{ ev.eventTimestampUtc | date:'HH:mm:ss' }}</td>
                            <td class="font-semibold text-white">{{ ev.eventType }}</td>
                            <td class="font-mono text-sky-400">{{ ev.sourceIp }}</td>
                            <td class="text-slate-300 truncate max-w-xs">{{ ev.description }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>

            <!-- Footer -->
            <div class="pt-4 border-t border-[#27354f] text-right">
              <button (click)="activeIncident.set(null)" class="btn btn-secondary btn-sm">Close Workspace</button>
            </div>
          </div>
        </div>
      }
    </div>
  `
})
export class IncidentsComponent implements OnInit {
  incidents = signal<Incident[]>([]);
  activeIncident = signal<Incident | null>(null);
  loading = signal(false);
  aiLoading = signal(false);
  aiAnalysis = signal<AiIncidentAnalysis | null>(null);

  statusFilter = '';
  severityFilter = '';
  searchTerm = '';

  newNoteText = '';
  resolutionSummary = '';
  selectedAnalystId = 'analyst@securewatch.local';

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.loadIncidents();
  }

  loadIncidents(): void {
    this.loading.set(true);
    const params: any = {
      pageSize: 30,
      status: this.statusFilter ? parseInt(this.statusFilter) : undefined,
      severity: this.severityFilter ? parseInt(this.severityFilter) : undefined,
      searchTerm: this.searchTerm || undefined
    };

    this.api.getIncidents(params).subscribe({
      next: (res) => {
        this.loading.set(false);
        if (res.success && res.data) {
          this.incidents.set(res.data.items);
        }
      },
      error: () => this.loading.set(false)
    });
  }

  openIncident(inc: Incident): void {
    this.api.getIncidentById(inc.id).subscribe({
      next: (res) => {
        if (res.success && res.data) {
          this.activeIncident.set(res.data);
          this.aiAnalysis.set(null);
        }
      }
    });
  }

  runAiAnalysis(): void {
    if (!this.activeIncident()) return;
    this.aiLoading.set(true);

    this.api.analyzeIncidentWithAi(this.activeIncident()!.id).subscribe({
      next: (res) => {
        this.aiLoading.set(false);
        if (res.success && res.data) {
          this.aiAnalysis.set(res.data);
        }
      },
      error: () => this.aiLoading.set(false)
    });
  }

  assignAnalyst(): void {
    if (!this.activeIncident()) return;
    this.api.assignIncident(this.activeIncident()!.id, this.selectedAnalystId).subscribe({
      next: (res) => {
        if (res.success && res.data) {
          this.activeIncident.update(i => i ? { ...i, statusName: 'Investigating', assignedAnalystName: res.data!.assignedAnalystName } : null);
          this.loadIncidents();
        }
      }
    });
  }

  addNote(): void {
    if (!this.activeIncident() || !this.newNoteText.trim()) return;

    this.api.addIncidentNote(this.activeIncident()!.id, this.newNoteText.trim()).subscribe({
      next: (res) => {
        if (res.success && res.data) {
          const notes = [...(this.activeIncident()!.notes || []), res.data];
          this.activeIncident.update(i => i ? { ...i, notes } : null);
          this.newNoteText = '';
        }
      }
    });
  }

  resolveIncident(): void {
    if (!this.activeIncident() || !this.resolutionSummary.trim()) return;

    this.api.resolveIncident(this.activeIncident()!.id, this.resolutionSummary.trim()).subscribe({
      next: (res) => {
        if (res.success && res.data) {
          this.activeIncident.update(i => i ? { ...i, statusName: 'Resolved', resolutionSummary: this.resolutionSummary } : null);
          this.loadIncidents();
        }
      }
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

  getStatusBadgeClass(status: string): string {
    switch (status?.toLowerCase()) {
      case 'resolved': return 'badge-success';
      case 'investigating': return 'badge-high';
      case 'escalated': return 'badge-critical';
      default: return 'badge-medium';
    }
  }

  getRiskColor(score: number): string {
    if (score >= 80) return 'text-rose-500';
    if (score >= 60) return 'text-orange-400';
    if (score >= 30) return 'text-amber-400';
    return 'text-sky-400';
  }
}

