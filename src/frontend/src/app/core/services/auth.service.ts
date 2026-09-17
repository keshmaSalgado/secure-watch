import { Injectable, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap, catchError, of } from 'rxjs';
import { ApiResponse, LoginResponse, UserProfile } from '../models/types';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly baseUrl = 'http://localhost:5000/api/v1/auth';

  // Signals
  readonly currentUser = signal<UserProfile | null>(this.getStoredUser());
  readonly isAuthenticated = computed(() => !!this.currentUser());
  readonly currentRole = computed(() => this.currentUser()?.role || '');

  constructor(private http: HttpClient, private router: Router) {}

  login(email: string, password: string): Observable<ApiResponse<LoginResponse>> {
    return this.http.post<ApiResponse<LoginResponse>>(`${this.baseUrl}/login`, { email, password }).pipe(
      tap(res => {
        if (res.success && res.data) {
          this.setSession(res.data);
        }
      })
    );
  }

  logout(): void {
    const token = this.getAccessToken();
    if (token) {
      this.http.post(`${this.baseUrl}/logout`, {}).subscribe({ error: () => {} });
    }
    localStorage.removeItem('securewatch_access_token');
    localStorage.removeItem('securewatch_refresh_token');
    localStorage.removeItem('securewatch_user');
    this.currentUser.set(null);
    this.router.navigate(['/login']);
  }

  getAccessToken(): string | null {
    return localStorage.getItem('securewatch_access_token');
  }

  getRefreshToken(): string | null {
    return localStorage.getItem('securewatch_refresh_token');
  }

  hasPermission(permission: string): boolean {
    const user = this.currentUser();
    if (!user) return false;
    if (user.role === 'SuperAdmin') return true;
    return user.permissions?.includes(permission) || false;
  }

  private setSession(authResult: LoginResponse): void {
    localStorage.setItem('securewatch_access_token', authResult.accessToken);
    localStorage.setItem('securewatch_refresh_token', authResult.refreshToken);
    localStorage.setItem('securewatch_user', JSON.stringify(authResult.user));
    this.currentUser.set(authResult.user);
  }

  private getStoredUser(): UserProfile | null {
    const raw = localStorage.getItem('securewatch_user');
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
}

