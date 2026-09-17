import { Injectable, signal } from '@angular/core';
import * as signalR from '@microsoft/signalr';
import { Subject } from 'rxjs';
import { SecurityEvent, ThreatDetection, Incident } from '../models/types';
import { AuthService } from './auth.service';

export interface AlertNotification {
  title: string;
  message: string;
  severity: string;
  timestamp: string;
}

@Injectable({
  providedIn: 'root'
})
export class SignalRService {
  private hubConnection: signalR.HubConnection | null = null;
  readonly connectionStatus = signal<'Connected' | 'Connecting' | 'Disconnected'>('Disconnected');
  readonly liveAlerts = signal<AlertNotification[]>([]);

  // Observable event streams
  readonly securityEvents$ = new Subject<SecurityEvent>();
  readonly threatDetections$ = new Subject<ThreatDetection>();
  readonly incidentCreated$ = new Subject<Incident>();
  readonly incidentUpdated$ = new Subject<Incident>();
  readonly alertReceived$ = new Subject<AlertNotification>();

  constructor(private authService: AuthService) {}

  startConnection(): void {
    if (this.hubConnection && this.hubConnection.state === signalR.HubConnectionState.Connected) {
      return;
    }

    this.connectionStatus.set('Connecting');

    this.hubConnection = new signalR.HubConnectionBuilder()
      .withUrl('http://localhost:5000/hubs/security', {
        accessTokenFactory: () => this.authService.getAccessToken() || '',
        transport: signalR.HttpTransportType.WebSockets | signalR.HttpTransportType.LongPolling
      })
      .withAutomaticReconnect([0, 2000, 5000, 10000])
      .configureLogging(signalR.LogLevel.Warning)
      .build();

    this.hubConnection.start()
      .then(() => {
        this.connectionStatus.set('Connected');
        this.registerHandlers();
      })
      .catch(err => {
        console.warn('SignalR Hub connection failed:', err);
        this.connectionStatus.set('Disconnected');
      });

    this.hubConnection.onreconnecting(() => this.connectionStatus.set('Connecting'));
    this.hubConnection.onreconnected(() => this.connectionStatus.set('Connected'));
    this.hubConnection.onclose(() => this.connectionStatus.set('Disconnected'));
  }

  stopConnection(): void {
    if (this.hubConnection) {
      this.hubConnection.stop();
      this.connectionStatus.set('Disconnected');
    }
  }

  private registerHandlers(): void {
    if (!this.hubConnection) return;

    this.hubConnection.on('ReceiveSecurityEvent', (event: SecurityEvent) => {
      this.securityEvents$.next(event);
    });

    this.hubConnection.on('ReceiveThreatDetection', (threat: ThreatDetection) => {
      this.threatDetections$.next(threat);
      this.pushAlert({
        title: `Threat: ${threat.threatTypeName}`,
        message: threat.detectionReason,
        severity: threat.severityName,
        timestamp: new Date().toLocaleTimeString()
      });
    });

    this.hubConnection.on('ReceiveIncidentCreated', (incident: Incident) => {
      this.incidentCreated$.next(incident);
      this.pushAlert({
        title: `New Incident Raised: ${incident.incidentCode}`,
        message: incident.title,
        severity: incident.severityName,
        timestamp: new Date().toLocaleTimeString()
      });
    });

    this.hubConnection.on('ReceiveIncidentUpdated', (incident: Incident) => {
      this.incidentUpdated$.next(incident);
    });

    this.hubConnection.on('ReceiveAlert', (alert: AlertNotification) => {
      this.alertReceived$.next(alert);
      this.pushAlert(alert);
    });
  }

  private pushAlert(alert: AlertNotification): void {
    const current = this.liveAlerts();
    this.liveAlerts.set([alert, ...current.slice(0, 9)]);
  }

  clearAlerts(): void {
    this.liveAlerts.set([]);
  }
}

