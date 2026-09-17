import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <aside class="w-64 bg-[#111827] border-r border-[#27354f] flex flex-col justify-between h-[calc(100vh-4rem)] sticky top-16 select-none">
      <div class="p-3 space-y-1">
        <div class="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-500 font-mono">
          Operations Center
        </div>

        <a routerLink="/dashboard" routerLinkActive="bg-[#172033] text-[#38BDF8] border-l-2 border-[#38BDF8]"
           class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-[#172033] hover:text-white transition">
          <i class="las la-chart-area text-lg text-slate-400"></i>
          <span>Overview</span>
        </a>

        <a routerLink="/monitoring" routerLinkActive="bg-[#172033] text-[#38BDF8] border-l-2 border-[#38BDF8]"
           class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-[#172033] hover:text-white transition">
          <i class="las la-satellite-dish text-lg text-slate-400"></i>
          <span>Live Monitoring</span>
          <span class="ml-auto w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
        </a>

        <a routerLink="/events" routerLinkActive="bg-[#172033] text-[#38BDF8] border-l-2 border-[#38BDF8]"
           class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-[#172033] hover:text-white transition">
          <i class="las la-stream text-lg text-slate-400"></i>
          <span>Security Events</span>
        </a>

        <a routerLink="/threats" routerLinkActive="bg-[#172033] text-[#38BDF8] border-l-2 border-[#38BDF8]"
           class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-[#172033] hover:text-white transition">
          <i class="las la-crosshairs text-lg text-slate-400"></i>
          <span>Threat Detection</span>
        </a>

        <a routerLink="/intelligence" routerLinkActive="bg-[#172033] text-[#38BDF8] border-l-2 border-[#38BDF8]"
           class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-[#172033] hover:text-white transition">
          <i class="las la-globe-americas text-lg text-slate-400"></i>
          <span>IP Intelligence</span>
        </a>

        <a routerLink="/incidents" routerLinkActive="bg-[#172033] text-[#38BDF8] border-l-2 border-[#38BDF8]"
           class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-[#172033] hover:text-white transition">
          <i class="las la-exclamation-triangle text-lg text-slate-400"></i>
          <span>Incidents</span>
        </a>

        <div class="pt-4 px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-500 font-mono">
          Intelligence & AI
        </div>

        <a routerLink="/ai-assistant" routerLinkActive="bg-[#172033] text-[#38BDF8] border-l-2 border-[#38BDF8]"
           class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-[#172033] hover:text-white transition">
          <i class="las la-brain text-lg text-indigo-400"></i>
          <span>AI Security Assistant</span>
          <span class="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-mono">ML</span>
        </a>

        @if (auth.hasPermission('Permissions.Users.Manage') || auth.currentRole() === 'SuperAdmin') {
          <div class="pt-4 px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-500 font-mono">
            Administration
          </div>

          <a routerLink="/admin" routerLinkActive="bg-[#172033] text-[#38BDF8] border-l-2 border-[#38BDF8]"
             class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:bg-[#172033] hover:text-white transition">
            <i class="las la-user-shield text-lg text-slate-400"></i>
            <span>Governance & Admin</span>
          </a>
        }
      </div>

      <!-- Bottom System Status Footer -->
      <div class="p-4 border-t border-[#27354f] bg-[#0d131f]">
        <div class="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span>Engine Status</span>
          <span class="text-emerald-400 font-mono font-medium">ONLINE</span>
        </div>
        <div class="w-full bg-[#1e293b] rounded-full h-1.5 overflow-hidden">
          <div class="bg-gradient-to-r from-[#38BDF8] to-[#22C55E] h-1.5 rounded-full w-full"></div>
        </div>
        <div class="text-[10px] text-slate-500 mt-2 font-mono flex items-center justify-between">
          <span>PostgreSQL + Redis</span>
          <span>FastAPI ML</span>
        </div>
      </div>
    </aside>
  `
})
export class SidebarComponent {
  constructor(public auth: AuthService) {}
}

