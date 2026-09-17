import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';
import { LoginComponent } from './features/auth/login.component';
import { DashboardComponent } from './features/dashboard/dashboard.component';
import { MonitoringComponent } from './features/monitoring/monitoring.component';
import { EventsComponent } from './features/events/events.component';
import { ThreatsComponent } from './features/threats/threats.component';
import { IntelligenceComponent } from './features/intelligence/intelligence.component';
import { IncidentsComponent } from './features/incidents/incidents.component';
import { AiAssistantComponent } from './features/ai-assistant/ai-assistant.component';
import { AdminComponent } from './features/admin/admin.component';

export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'dashboard', component: DashboardComponent, canActivate: [authGuard] },
  { path: 'monitoring', component: MonitoringComponent, canActivate: [authGuard] },
  { path: 'events', component: EventsComponent, canActivate: [authGuard] },
  { path: 'threats', component: ThreatsComponent, canActivate: [authGuard] },
  { path: 'intelligence', component: IntelligenceComponent, canActivate: [authGuard] },
  { path: 'incidents', component: IncidentsComponent, canActivate: [authGuard] },
  { path: 'ai-assistant', component: AiAssistantComponent, canActivate: [authGuard] },
  { path: 'admin', component: AdminComponent, canActivate: [authGuard] },
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: '**', redirectTo: 'dashboard' }
];
