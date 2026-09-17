import { Component, EventEmitter, Output, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../core/services/api.service';

@Component({
  selector: 'app-simulator-modal',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div class="bg-[#172033] border border-[#27354f] rounded-2xl w-full max-w-xl p-6 shadow-2xl relative">
        <!-- Close button -->
        <button (click)="close.emit()" class="absolute top-5 right-5 text-slate-400 hover:text-white">
          <i class="las la-times text-xl"></i>
        </button>

        <!-- Header -->
        <div class="flex items-center gap-3 mb-4">
          <div class="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <i class="las la-radiation text-2xl"></i>
          </div>
          <div>
            <h2 class="text-lg font-bold text-white">Security Event Simulator</h2>
            <p class="text-xs text-slate-400">Safely inject realistic synthetic attack scenarios into SIEM telemetry</p>
          </div>
        </div>

        <!-- Scenarios Grid -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 my-4">
          <button (click)="runScenario('normal-login')" [disabled]="loading()"
                  class="p-3 rounded-xl bg-[#111827] border border-[#27354f] hover:border-emerald-500/50 text-left transition flex flex-col justify-between">
            <div class="flex items-center justify-between mb-1">
              <span class="font-semibold text-xs text-slate-200">Normal Routine Login</span>
              <span class="badge badge-low text-[10px]">Baseline</span>
            </div>
            <p class="text-[11px] text-slate-400">Valid credentials from trusted internal subnet 10.0.0.15.</p>
          </button>

          <button (click)="runScenario('brute-force-fast')" [disabled]="loading()"
                  class="p-3 rounded-xl bg-[#111827] border border-[#27354f] hover:border-amber-500/50 text-left transition flex flex-col justify-between">
            <div class="flex items-center justify-between mb-1">
              <span class="font-semibold text-xs text-slate-200">Rapid Brute Force</span>
              <span class="badge badge-high text-[10px]">Rule 01</span>
            </div>
            <p class="text-[11px] text-slate-400">6 consecutive authentication failures within 60 seconds.</p>
          </button>

          <button (click)="runScenario('brute-force-aggressive')" [disabled]="loading()"
                  class="p-3 rounded-xl bg-[#111827] border border-[#27354f] hover:border-rose-500/50 text-left transition flex flex-col justify-between">
            <div class="flex items-center justify-between mb-1">
              <span class="font-semibold text-xs text-slate-200">Aggressive Flood</span>
              <span class="badge badge-critical text-[10px]">Rule 02</span>
            </div>
            <p class="text-[11px] text-slate-400">22 automated failed login attempts from botnet agent.</p>
          </button>

          <button (click)="runScenario('credential-spray')" [disabled]="loading()"
                  class="p-3 rounded-xl bg-[#111827] border border-[#27354f] hover:border-indigo-500/50 text-left transition flex flex-col justify-between">
            <div class="flex items-center justify-between mb-1">
              <span class="font-semibold text-xs text-slate-200">Credential Spray</span>
              <span class="badge badge-high text-[10px]">Rule 04</span>
            </div>
            <p class="text-[11px] text-slate-400">Password spray testing 4 distinct user accounts from single IP.</p>
          </button>

          <button (click)="runScenario('malicious-ip')" [disabled]="loading()"
                  class="p-3 rounded-xl bg-[#111827] border border-[#27354f] hover:border-rose-500/50 text-left transition flex flex-col justify-between">
            <div class="flex items-center justify-between mb-1">
              <span class="font-semibold text-xs text-slate-200">Malicious Threat Feed IP</span>
              <span class="badge badge-critical text-[10px]">Rule 05</span>
            </div>
            <p class="text-[11px] text-slate-400">Activity from hostile botnet 198.51.100.42 (Score: 95/100).</p>
          </button>

          <button (click)="runScenario('tor-proxy')" [disabled]="loading()"
                  class="p-3 rounded-xl bg-[#111827] border border-[#27354f] hover:border-indigo-500/50 text-left transition flex flex-col justify-between">
            <div class="flex items-center justify-between mb-1">
              <span class="font-semibold text-xs text-slate-200">Tor Exit Node Login</span>
              <span class="badge badge-medium text-[10px]">Rule 07</span>
            </div>
            <p class="text-[11px] text-slate-400">Anonymized session from Frankfurt Tor relay 185.220.101.5.</p>
          </button>
        </div>

        <!-- Result / Feedback box -->
        @if (feedbackMessage()) {
          <div class="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs mb-4 flex items-center gap-2">
            <i class="las la-check-circle text-base"></i>
            <span>{{ feedbackMessage() }}</span>
          </div>
        }

        <!-- Bottom bar with Factory Reset button -->
        <div class="pt-4 border-t border-[#27354f] flex items-center justify-between">
          <button (click)="resetDemo()" [disabled]="loading()" class="btn btn-secondary btn-sm text-slate-400 hover:text-white flex items-center gap-1.5">
            <i class="las la-undo-alt"></i>
            <span>Reset Demo Baseline</span>
          </button>

          <button (click)="close.emit()" class="btn btn-primary btn-sm">
            Done
          </button>
        </div>
      </div>
    </div>
  `
})
export class SimulatorModalComponent {
  @Output() close = new EventEmitter<void>();
  loading = signal(false);
  feedbackMessage = signal<string | null>(null);

  constructor(private api: ApiService) {}

  runScenario(type: string): void {
    this.loading.set(true);
    this.feedbackMessage.set(null);

    this.api.triggerSimulation(type).subscribe({
      next: (res) => {
        this.loading.set(false);
        this.feedbackMessage.set(res.data || 'Scenario executed.');
      },
      error: (err) => {
        this.loading.set(false);
        this.feedbackMessage.set(err.error?.message || 'Error executing scenario.');
      }
    });
  }

  resetDemo(): void {
    this.loading.set(true);
    this.feedbackMessage.set(null);

    this.api.resetDemoData().subscribe({
      next: () => {
        this.loading.set(false);
        this.feedbackMessage.set('Demo data reset to pristine baseline state.');
      },
      error: () => {
        this.loading.set(false);
        this.feedbackMessage.set('Error resetting demo baseline.');
      }
    });
  }
}

