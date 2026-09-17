import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { App } from './app';
import { AuthService } from './core/services/auth.service';
import { SignalRService } from './core/services/signalr.service';
import { signal } from '@angular/core';

describe('App', () => {
  let mockAuthService: jasmine.SpyObj<AuthService>;
  let mockSignalRService: jasmine.SpyObj<SignalRService>;

  beforeEach(async () => {
    mockAuthService = jasmine.createSpyObj('AuthService', ['isAuthenticated', 'logout', 'login'], {
      currentUser: signal(null),
      token: signal(null)
    });
    mockAuthService.isAuthenticated.and.returnValue(false);

    mockSignalRService = jasmine.createSpyObj('SignalRService', ['startConnection', 'stopConnection'], {
      isConnected: signal(false),
      liveEvents: signal([]),
      alerts: signal([])
    });

    await TestBed.configureTestingModule({
      imports: [App],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        { provide: AuthService, useValue: mockAuthService },
        { provide: SignalRService, useValue: mockSignalRService }
      ]
    }).compileComponents();
  });

  it('should create the root application component', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it('should toggle cyber attack simulator modal', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    expect(app.showSimulator()).toBeFalse();

    app.openSimulator();
    expect(app.showSimulator()).toBeTrue();

    app.closeSimulator();
    expect(app.showSimulator()).toBeFalse();
  });

  it('should initialize SignalR connection if user is authenticated', () => {
    mockAuthService.isAuthenticated.and.returnValue(true);
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    expect(mockSignalRService.startConnection).toHaveBeenCalled();
  });
});
