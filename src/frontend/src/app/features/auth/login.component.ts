import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="min-h-screen bg-[#0B1120] flex items-center justify-center p-4 relative overflow-hidden">
      <!-- Background Cyber Grid Effect -->
      <div class="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-40"></div>
      <div class="absolute -top-40 -left-40 w-96 h-96 bg-[#38BDF8]/10 rounded-full blur-3xl pointer-events-none"></div>
      <div class="absolute -bottom-40 -right-40 w-96 h-96 bg-[#6366F1]/10 rounded-full blur-3xl pointer-events-none"></div>

      <div class="w-full max-w-md relative z-10">
        <!-- Logo Header -->
        <div class="text-center mb-8">
          <div class="w-14 h-14 mx-auto rounded-2xl bg-gradient-to-tr from-[#38BDF8] to-[#6366F1] flex items-center justify-center shadow-lg shadow-[#38BDF8]/20 mb-3">
            <i class="las la-shield-alt text-3xl text-[#0B1120]"></i>
          </div>
          <h1 class="text-2xl font-extrabold tracking-wide text-white">SECURE<span class="text-[#38BDF8]">WATCH</span></h1>
          <p class="text-xs text-slate-400 mt-1">Enterprise SIEM & AI Threat Detection Platform</p>
        </div>

        <!-- Login Card -->
        <div class="sec-card shadow-2xl border-[#27354f]/80 p-8">
          @if (errorMessage()) {
            <div class="p-3 mb-5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center gap-2">
              <i class="las la-exclamation-circle text-base"></i>
              <span>{{ errorMessage() }}</span>
            </div>
          }

          <form (ngSubmit)="onSubmit()" class="space-y-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">Email Address</label>
              <div class="relative">
                <i class="las la-envelope absolute left-3 top-2.5 text-slate-400 text-lg"></i>
                <input type="email" [(ngModel)]="email" name="email" required
                       placeholder="analyst@securewatch.local"
                       class="form-input pl-10 text-sm">
              </div>
            </div>

            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">Password</label>
              <div class="relative">
                <i class="las la-lock absolute left-3 top-2.5 text-slate-400 text-lg"></i>
                <input type="password" [(ngModel)]="password" name="password" required
                       placeholder="••••••••••••"
                       class="form-input pl-10 text-sm">
              </div>
            </div>

            <button type="submit" [disabled]="loading()" class="btn btn-primary w-full py-2.5 mt-2 text-sm font-semibold">
              @if (loading()) {
                <i class="las la-spinner animate-spin text-lg"></i>
                <span>Authenticating...</span>
              } @else {
                <i class="las la-sign-in-alt text-lg"></i>
                <span>Sign In to Console</span>
              }
            </button>
          </form>

          <!-- Quick 1-Click Demo Profiles -->
          <div class="mt-8 pt-6 border-t border-[#27354f]">
            <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-3 text-center font-mono">
              Demo Access (Click to autofill)
            </div>

            <div class="grid grid-cols-2 gap-2 text-xs">
              <button type="button" (click)="quickLogin('admin@securewatch.local')"
                      class="p-2 rounded-lg bg-[#111827] border border-[#27354f] hover:border-[#38BDF8]/50 text-left transition">
                <div class="font-semibold text-white">Super Admin</div>
                <div class="text-[10px] text-slate-400 font-mono">admin&#64;securewatch</div>
              </button>

              <button type="button" (click)="quickLogin('secadmin@securewatch.local')"
                      class="p-2 rounded-lg bg-[#111827] border border-[#27354f] hover:border-[#38BDF8]/50 text-left transition">
                <div class="font-semibold text-white">SecOps Admin</div>
                <div class="text-[10px] text-slate-400 font-mono">secadmin&#64;securewatch</div>
              </button>

              <button type="button" (click)="quickLogin('analyst@securewatch.local')"
                      class="p-2 rounded-lg bg-[#111827] border border-[#27354f] hover:border-[#38BDF8]/50 text-left transition">
                <div class="font-semibold text-white">SOC Analyst</div>
                <div class="text-[10px] text-slate-400 font-mono">analyst&#64;securewatch</div>
              </button>

              <button type="button" (click)="quickLogin('auditor@securewatch.local')"
                      class="p-2 rounded-lg bg-[#111827] border border-[#27354f] hover:border-[#38BDF8]/50 text-left transition">
                <div class="font-semibold text-white">Auditor</div>
                <div class="text-[10px] text-slate-400 font-mono">auditor&#64;securewatch</div>
              </button>
            </div>
          </div>
        </div>

        <!-- Security Compliance Notice -->
        <div class="text-center mt-6 text-[11px] text-slate-500 font-mono">
          <span>Protected by Rate Limiting & Refresh Token Rotation</span>
        </div>
      </div>
    </div>
  `
})
export class LoginComponent {
  email = '';
  password = '';
  loading = signal(false);
  errorMessage = signal<string | null>(null);

  constructor(private authService: AuthService, private router: Router) {}

  quickLogin(demoEmail: string): void {
    this.email = demoEmail;
    this.password = 'SecureWatch@2026!';
    this.onSubmit();
  }

  onSubmit(): void {
    if (!this.email || !this.password) {
      this.errorMessage.set('Please enter both email and password.');
      return;
    }

    this.loading.set(true);
    this.errorMessage.set(null);

    this.authService.login(this.email, this.password).subscribe({
      next: (res) => {
        this.loading.set(false);
        if (res.success) {
          this.router.navigate(['/dashboard']);
        } else {
          this.errorMessage.set(res.message || 'Authentication failed.');
        }
      },
      error: (err) => {
        this.loading.set(false);
        this.errorMessage.set(err.error?.message || 'Unable to connect to security authentication service.');
      }
    });
  }
}

