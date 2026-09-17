import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { NavbarComponent } from './shared/components/navbar.component';
import { SidebarComponent } from './shared/components/sidebar.component';
import { SimulatorModalComponent } from './features/simulator/simulator-modal.component';
import { AuthService } from './core/services/auth.service';
import { SignalRService } from './core/services/signalr.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, NavbarComponent, SidebarComponent, SimulatorModalComponent],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit {
  showSimulator = signal(false);

  constructor(public auth: AuthService, private signalr: SignalRService) {}

  ngOnInit(): void {
    if (this.auth.isAuthenticated()) {
      this.signalr.startConnection();
    }
  }

  openSimulator(): void {
    this.showSimulator.set(true);
  }

  closeSimulator(): void {
    this.showSimulator.set(false);
  }
}
