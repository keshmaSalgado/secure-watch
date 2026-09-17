import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { AiReport, AnomalyDetectionResult } from '../../core/models/types';

interface ChatMessage {
  sender: 'user' | 'ai';
  text: string;
  time: string;
  referenced?: string[];
  followups?: string[];
}

@Component({
  selector: 'app-ai-assistant',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="space-y-6">
      <!-- Title Bar -->
      <div class="flex items-center justify-between pb-4 border-b border-[#27354f]">
        <div>
          <h1 class="text-xl font-bold text-white flex items-center gap-2">
            <span>AI Security Assistant & ML Lab</span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">FastAPI + Scikit-Learn</span>
          </h1>
          <p class="text-xs text-slate-400">Natural language threat querying, Isolation Forest anomaly scoring, and automated executive posture reports</p>
        </div>

        <!-- Mode Switcher Tabs -->
        <div class="flex items-center p-1 rounded-xl bg-[#111827] border border-[#27354f] text-xs">
          <button (click)="activeTab.set('chat')" [ngClass]="{ 'bg-[#1e293b] text-[#38BDF8] shadow': activeTab() === 'chat' }" class="px-3 py-1.5 rounded-lg text-slate-300 font-medium transition">
            <i class="las la-comments mr-1"></i>Copilot Chat
          </button>
          <button (click)="activeTab.set('anomaly')" [ngClass]="{ 'bg-[#1e293b] text-[#38BDF8] shadow': activeTab() === 'anomaly' }" class="px-3 py-1.5 rounded-lg text-slate-300 font-medium transition">
            <i class="las la-project-diagram mr-1"></i>Isolation Forest
          </button>
          <button (click)="activeTab.set('reports')" [ngClass]="{ 'bg-[#1e293b] text-[#38BDF8] shadow': activeTab() === 'reports' }" class="px-3 py-1.5 rounded-lg text-slate-300 font-medium transition">
            <i class="las la-file-alt mr-1"></i>Executive Reports
          </button>
        </div>
      </div>

      <!-- Tab 1: AI Copilot Chat -->
      @if (activeTab() === 'chat') {
        <div class="sec-card p-0 flex flex-col h-[650px] overflow-hidden">
          <!-- Chat Header -->
          <div class="p-4 bg-[#111827] border-b border-[#27354f] flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center text-indigo-300">
                <i class="las la-robot text-lg"></i>
              </div>
              <div>
                <h3 class="text-xs font-bold text-white uppercase tracking-wider font-mono">SOC Virtual Assistant</h3>
                <span class="text-[10px] text-emerald-400 flex items-center gap-1">
                  <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> Online & Grounded in Telemetry
                </span>
              </div>
            </div>

            <!-- Quick Questions Dropdown -->
            <div class="flex items-center gap-2">
              <span class="text-[11px] text-slate-500 hidden sm:inline font-mono">Suggested:</span>
              <button (click)="askPreset('What were the most critical security incidents today?')" class="btn btn-secondary btn-sm text-[10px] py-1">
                Critical Incidents
              </button>
              <button (click)="askPreset('Which IP addresses generated the most suspicious events?')" class="btn btn-secondary btn-sm text-[10px] py-1">
                Top Hostile IPs
              </button>
            </div>
          </div>

          <!-- Messages Stream -->
          <div class="flex-1 p-4 overflow-y-auto space-y-4">
            @for (msg of chatMessages(); track $index) {
              <div class="flex gap-3" [ngClass]="{ 'justify-end': msg.sender === 'user' }">
                @if (msg.sender === 'ai') {
                  <div class="w-7 h-7 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex-shrink-0 flex items-center justify-center text-indigo-400">
                    <i class="las la-brain text-sm"></i>
                  </div>
                }

                <div class="max-w-2xl rounded-2xl p-4 text-xs space-y-2"
                     [ngClass]="msg.sender === 'user' ? 'bg-[#38BDF8] text-[#0B1120] font-medium' : 'bg-[#111827] border border-[#27354f] text-slate-200'">
                  <div class="whitespace-pre-wrap leading-relaxed">{{ msg.text }}</div>

                  <!-- Referenced Entities Pills -->
                  @if (msg.referenced && msg.referenced.length > 0) {
                    <div class="pt-2 border-t border-[#27354f] flex flex-wrap gap-1.5 items-center">
                      <span class="text-[10px] text-slate-500 font-mono">Correlated:</span>
                      @for (ref of msg.referenced; track ref) {
                        <span class="px-2 py-0.5 rounded bg-[#172033] border border-[#27354f] font-mono text-[10px] text-[#38BDF8]">
                          {{ ref }}
                        </span>
                      }
                    </div>
                  }

                  <!-- Suggested Follow-ups -->
                  @if (msg.followups && msg.followups.length > 0) {
                    <div class="pt-2 border-t border-[#27354f]/50 space-y-1">
                      <span class="text-[10px] text-slate-400 font-semibold">Suggested follow-ups:</span>
                      <div class="flex flex-wrap gap-1.5">
                        @for (fu of msg.followups; track fu) {
                          <button (click)="askPreset(fu)" class="text-[10px] px-2 py-1 rounded-lg bg-[#1e293b] hover:bg-[#334155] text-slate-300 transition text-left">
                            &rarr; {{ fu }}
                          </button>
                        }
                      </div>
                    </div>
                  }
                </div>

                @if (msg.sender === 'user') {
                  <div class="w-7 h-7 rounded-lg bg-[#38BDF8]/20 border border-[#38BDF8]/40 flex-shrink-0 flex items-center justify-center text-[#38BDF8]">
                    <i class="las la-user text-sm"></i>
                  </div>
                }
              </div>
            }

            @if (chatLoading()) {
              <div class="flex items-center gap-2 text-xs text-slate-400 p-2">
                <i class="las la-spinner animate-spin text-base text-indigo-400"></i>
                <span>Querying SIEM telemetry & generating response...</span>
              </div>
            }
          </div>

          <!-- Chat Input Bar -->
          <form (ngSubmit)="sendChat()" class="p-3 bg-[#111827] border-t border-[#27354f] flex gap-2">
            <input type="text" [(ngModel)]="currentQuery" name="currentQuery" placeholder="Ask anything about security incidents, IP threats, or trends..."
                   class="form-input text-xs flex-1">
            <button type="submit" [disabled]="chatLoading() || !currentQuery.trim()" class="btn btn-primary text-xs px-5">
              <i class="las la-paper-plane text-base"></i>
              <span>Send</span>
            </button>
          </form>
        </div>
      }

      <!-- Tab 2: Isolation Forest Anomaly Detection -->
      @if (activeTab() === 'anomaly') {
        <div class="space-y-4">
          <div class="sec-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <h3 class="font-bold text-sm text-white">Isolation Forest Unsupervised Model</h3>
              <p class="text-xs text-slate-400">Trained on multi-dimensional telemetry (failed login counts, hour deviations, target account distribution, IP volatility)</p>
            </div>
            <button (click)="runAnomalyDetection()" [disabled]="anomalyLoading()" class="btn btn-primary btn-sm flex items-center gap-1.5">
              <i class="las la-microchip text-base" [ngClass]="{ 'animate-spin': anomalyLoading() }"></i>
              <span>{{ anomalyLoading() ? 'Running Model...' : 'Execute Anomaly Scan' }}</span>
            </button>
          </div>

          @if (anomalyResult()) {
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div class="sec-card p-4">
                <div class="text-[11px] font-bold uppercase text-slate-400">Evaluated Events</div>
                <div class="text-3xl font-black font-mono text-white mt-1">{{ anomalyResult()!.analyzedEventsCount }}</div>
              </div>
              <div class="sec-card p-4">
                <div class="text-[11px] font-bold uppercase text-slate-400">Statistical Outliers Found</div>
                <div class="text-3xl font-black font-mono text-rose-500 mt-1">{{ anomalyResult()!.anomaliesDetectedCount }}</div>
              </div>
              <div class="sec-card p-4">
                <div class="text-[11px] font-bold uppercase text-slate-400">Model Contamination Setting</div>
                <div class="text-3xl font-black font-mono text-indigo-400 mt-1">5.0%</div>
              </div>
            </div>

            <div class="sec-card p-0 overflow-hidden">
              <div class="p-4 bg-[#111827] border-b border-[#27354f]">
                <h4 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">Detected Behavioral Outliers</h4>
              </div>
              <table class="sec-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Account</th>
                    <th>Anomaly Magnitude</th>
                    <th>Outlier Analysis Reason</th>
                  </tr>
                </thead>
                <tbody>
                  @for (item of anomalyResult()!.anomalyItems; track item.eventId) {
                    <tr>
                      <td class="font-mono text-xs text-sky-400">{{ item.sourceIp }}</td>
                      <td class="text-xs text-slate-300">{{ item.username || '—' }}</td>
                      <td>
                        <span class="badge badge-critical font-mono">{{ item.anomalyScore }}</span>
                      </td>
                      <td class="text-xs text-slate-200">{{ item.reason }}</td>
                    </tr>
                  }
                  @if (anomalyResult()!.anomalyItems.length === 0) {
                    <tr>
                      <td colspan="4" class="text-center py-8 text-slate-500 text-xs">No statistical anomalies detected in current sample window.</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        </div>
      }

      <!-- Tab 3: Executive Posture Reports -->
      @if (activeTab() === 'reports') {
        <div class="space-y-4">
          <div class="sec-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <h3 class="font-bold text-sm text-white">AI-Generated Executive Posture Assessment</h3>
              <p class="text-xs text-slate-400">Automated synthesis of telemetry volume, threat vectors, and recommended mitigations</p>
            </div>
            <div class="flex items-center gap-2">
              <button (click)="generateReport('DailySummary')" [disabled]="reportLoading()" class="btn btn-secondary btn-sm">Daily Summary</button>
              <button (click)="generateReport('WeeklyThreats')" [disabled]="reportLoading()" class="btn btn-primary btn-sm">Weekly Threat Posture</button>
            </div>
          </div>

          @if (report()) {
            <div class="sec-card p-6 space-y-6">
              <div class="flex items-center justify-between pb-4 border-b border-[#27354f]">
                <div>
                  <h2 class="text-base font-bold text-white">{{ report()!.title }}</h2>
                  <span class="text-xs text-slate-400 font-mono">Generated: {{ report()!.generatedAtUtc | date:'yyyy-MM-dd HH:mm:ss' }} UTC</span>
                </div>
                <span class="badge badge-low text-xs">AI Generated</span>
              </div>

              <!-- Executive Summary -->
              <div>
                <h4 class="text-xs font-bold uppercase text-slate-400 tracking-wider font-mono mb-2">Executive Overview</h4>
                <p class="text-xs text-slate-200 leading-relaxed bg-[#111827] p-4 rounded-xl border border-[#27354f]">
                  {{ report()!.executiveSummary }}
                </p>
              </div>

              <!-- Key Observations & Critical Risks Grid -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div class="p-4 rounded-xl bg-[#111827] border border-[#27354f]">
                  <h4 class="font-bold uppercase text-sky-400 font-mono mb-2">Key Observations</h4>
                  <ul class="list-disc list-inside space-y-1.5 text-slate-300">
                    @for (obs of report()!.keyObservations; track $index) {
                      <li>{{ obs }}</li>
                    }
                  </ul>
                </div>

                <div class="p-4 rounded-xl bg-[#111827] border border-[#27354f]">
                  <h4 class="font-bold uppercase text-rose-400 font-mono mb-2">Primary Threat Vectors</h4>
                  <ul class="list-disc list-inside space-y-1.5 text-slate-300">
                    @for (risk of report()!.criticalRiskAreas; track $index) {
                      <li>{{ risk }}</li>
                    }
                  </ul>
                </div>
              </div>

              <!-- Recommended Mitigations -->
              <div>
                <h4 class="text-xs font-bold uppercase text-slate-400 tracking-wider font-mono mb-2">Recommended SOC Mitigations</h4>
                <div class="space-y-2 text-xs">
                  @for (mit of report()!.recommendedMitigations; track $index) {
                    <div class="p-3 rounded-lg bg-[#111827] border border-[#27354f] text-slate-200">
                      {{ mit }}
                    </div>
                  }
                </div>
              </div>
            </div>
          }
        </div>
      }
    </div>
  `
})
export class AiAssistantComponent implements OnInit {
  activeTab = signal<'chat' | 'anomaly' | 'reports'>('chat');

  // Chat state
  chatMessages = signal<ChatMessage[]>([
    {
      sender: 'ai',
      text: "Hello! I am your SecureWatch AI Security Copilot. I analyze live event streams, explain risk scores, run Isolation Forest anomaly checks, and synthesize incidents.",
      time: 'Just now',
      followups: [
        "What were the most critical security incidents today?",
        "Which IP addresses generated the most suspicious events?"
      ]
    }
  ]);
  currentQuery = '';
  chatLoading = signal(false);

  // Anomaly state
  anomalyResult = signal<AnomalyDetectionResult | null>(null);
  anomalyLoading = signal(false);

  // Reports state
  report = signal<AiReport | null>(null);
  reportLoading = signal(false);

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.runAnomalyDetection();
  }

  sendChat(): void {
    if (!this.currentQuery.trim()) return;

    const query = this.currentQuery.trim();
    this.currentQuery = '';

    const history = this.chatMessages();
    this.chatMessages.set([
      ...history,
      { sender: 'user', text: query, time: new Date().toLocaleTimeString() }
    ]);

    this.chatLoading.set(true);

    this.api.chatWithAi(query).subscribe({
      next: (res) => {
        this.chatLoading.set(false);
        if (res.success && res.data) {
          this.chatMessages.set([
            ...this.chatMessages(),
            {
              sender: 'ai',
              text: res.data.answer,
              time: new Date().toLocaleTimeString(),
              referenced: res.data.referencedEntities,
              followups: res.data.suggestedFollowups
            }
          ]);
        }
      },
      error: () => this.chatLoading.set(false)
    });
  }

  askPreset(query: string): void {
    this.currentQuery = query;
    this.sendChat();
  }

  runAnomalyDetection(): void {
    this.anomalyLoading.set(true);
    this.api.detectAnomalies().subscribe({
      next: (res) => {
        this.anomalyLoading.set(false);
        if (res.success && res.data) {
          this.anomalyResult.set(res.data);
        }
      },
      error: () => this.anomalyLoading.set(false)
    });
  }

  generateReport(type: string): void {
    this.reportLoading.set(true);
    this.api.generateAiReport(type).subscribe({
      next: (res) => {
        this.reportLoading.set(false);
        if (res.success && res.data) {
          this.report.set(res.data);
        }
      },
      error: () => this.reportLoading.set(false)
    });
  }
}

