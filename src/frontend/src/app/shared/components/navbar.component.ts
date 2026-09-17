import { Component, EventEmitter, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../core/services/auth.service';
import { SignalRService } from '../../core/services/signalr.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule],
  template: `
    <header class="h-16 border-b border-[#27354f] bg-[#111827] px-6 flex items-center justify-between sticky top-0 z-40">
      <!-- Left: Platform Brand & Live Signal Indicator -->
      <div class="flex items-center gap-4">
        <div class="flex items-center gap-2">
          <div class="w-8 h-8 rounded-lg bg-gradient-to-tr from-[#38BDF8] to-[#6366F1] flex items-center justify-center font-bold text-white shadow-md shadow-[#38BDF8]/20">
            <i class="las la-shield-alt text-xl text-[#0B1120]"></i>
          </div>
          <span class="font-bold text-lg tracking-wider text-white">SECURE<span class="text-[#38BDF8]">WATCH</span></span>
          <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-[#1e293b] text-[#38BDF8] border border-[#38BDF8]/30">SIEM v2.6</span>
        </div>

        <!-- Real-time SignalR Status Indicator -->
        <div class="flex items-center gap-2 px-3 py-1 rounded-full bg-[#172033] border border-[#27354f] text-xs">
          <span class="w-2 h-2 rounded-full"
                [ngClass]="{
                  'bg-emerald-400 animate-pulse': signalr.connectionStatus() === 'Connected',
                  'bg-amber-400 animate-ping': signalr.connectionStatus() === 'Connecting',
                  'bg-rose-500': signalr.connectionStatus() === 'Disconnected'
                }"></span>
          <span class="text-xs text-slate-300 font-mono">Stream: {{ signalr.connectionStatus() }}</span>
        </div>
      </div>

      <!-- Right: Action Tools & User Profile -->
      <div class="flex items-center gap-3">
        <!-- Attack Simulator Button -->
        <button (click)="openSimulator.emit()" class="btn btn-secondary btn-sm text-amber-400 border-amber-500/30 hover:bg-amber-500/10 flex items-center gap-1.5">
          <i class="las la-bolt text-base text-amber-400"></i>
          <span>Attack Simulator</span>
        </button>

        <!-- Notification Bell Dropdown -->
        <div class="relative">
          <button (click)="toggleAlerts()" class="w-9 h-9 rounded-lg bg-[#172033] border border-[#27354f] flex items-center justify-center text-slate-300 hover:text-white hover:border-[#38BDF8]/50 relative">
            <i class="las la-bell text-lg"></i>
            @if (signalr.liveAlerts().length > 0) {
              <span class="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-[10px] font-bold text-white flex items-center justify-center">
                {{ signalr.liveAlerts().length }}
              </span>
            }
          </button>

          <!-- Notification Drawer -->
          @if (showAlerts) {
            <div class="absolute right-0 mt-2 w-80 bg-[#172033] border border-[#27354f] rounded-xl shadow-2xl p-3 z-50">
              <div class="flex items-center justify-between pb-2 border-b border-[#27354f]">
                <span class="text-xs font-semibold uppercase text-slate-400 tracking-wider">Live Security Alerts</span>
                <button (click)="signalr.clearAlerts()" class="text-[11px] text-[#38BDF8] hover:underline">Clear all</button>
              </div>
              <div class="mt-2 max-h-64 overflow-y-auto space-y-2">
                @for (alert of signalr.liveAlerts(); track $index) {
                  <div class="p-2 rounded-lg bg-[#111827] border border-[#27354f] text-xs">
                    <div class="flex items-center justify-between text-slate-400 text-[10px] mb-1">
                      <span class="badge" [ngClass]="alert.severity === 'Critical' ? 'badge-critical' : 'badge-high'">{{ alert.severity }}</span>
                      <span>{{ alert.timestamp }}</span>
                    </div>
                    <div class="font-medium text-slate-200">{{ alert.title }}</div>
                    <div class="text-[11px] text-slate-400 mt-0.5 line-clamp-2">{{ alert.message }}</div>
                  </div>
                }
                @if (signalr.liveAlerts().length === 0) {
                  <div class="text-center py-6 text-xs text-slate-500">
                    No active threat alerts in buffer.
                  </div>
                }
              </div>
            </div>
          }
        </div>

        <!-- User Profile Dropdown -->
        <div class="flex items-center gap-3 pl-3 border-l border-[#27354f]">
          <div class="text-right hidden sm:block">
            <div class="text-xs font-semibold text-white">{{ auth.currentUser()?.fullName }}</div>
            <div class="text-[11px] font-mono text-[#38BDF8]">{{ auth.currentUser()?.role }}</div>
          </div>
          <button (click)="auth.logout()" title="Logout" class="w-8 h-8 rounded-lg bg-[#1e293b] border border-[#27354f] flex items-center justify-center text-slate-400 hover:text-rose-400 hover:border-rose-500/50 transition">
            <i class="las la-sign-out-alt text-base"></i>
          </button>
        </div>
      </div>
    </header>
  `
})
export class NavbarComponent {
  @Output() openSimulator = new EventEmitter<void>();
  showAlerts = false;

  constructor(public auth: AuthService, public signalr: SignalRService) {}

  toggleAlerts(): void {
    this.showAlerts = !this.showAlerts;
  }
}

