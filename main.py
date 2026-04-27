"""
🛡️ NetGuard AI - Backend Security Engine
Framework: FastAPI (Asynchronous Python)
Description: 
    This server simulates the backend of a Security Operations Center (SOC). 
    It processes raw network telemetry, runs heuristic threat detection algorithms, 
    and generates AI-driven security recommendations based on traffic patterns.
"""

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
import random
import time
from datetime import datetime

app = FastAPI(title="NetGuard AI Backend")

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Data Models ---

class Packet(BaseModel):
    source_ip: str
    target_port: int
    protocol: str
    payload_size: int
    timestamp: float

class ThreatAlert(BaseModel):
    id: str
    type: str
    severity: str
    source_ip: str
    description: str
    timestamp: str

class SecurityInsight(BaseModel):
    engine: str
    summary: str
    recommendation: str

# --- In-Memory State & Telemetry ---

# Storage for the last 1000 packets for analysis
telemetry_buffer: List[Packet] = []
active_threats: List[ThreatAlert] = []
total_packets_processed = 0

# --- Heuristic Threat Engine ---

class ThreatEngine:
    """
    Simulates real-time packet analysis logic to identify 
    suspicious network behavioral patterns.
    """
    
    @staticmethod
    def detect_ddos(packets: List[Packet], threshold: int = 50) -> Optional[ThreatAlert]:
        """Checks if a single IP is flooding the network (DDoS)."""
        if not packets: return None
        
        ip_counts = {}
        for p in packets:
            ip_counts[p.source_ip] = ip_counts.get(p.source_ip, 0) + 1
        
        for ip, count in ip_counts.items():
            if count > threshold:
                return ThreatAlert(
                    id=f"DDS-{int(time.time())}",
                    type="DDoS Attack",
                    severity="CRITICAL",
                    source_ip=ip,
                    description=f"Traffic spike detected: {count} packets in 5s window.",
                    timestamp=datetime.now().isoformat()
                )
        return None

    @staticmethod
    def detect_port_scan(packets: List[Packet], port_threshold: int = 10) -> Optional[ThreatAlert]:
        """Checks if an IP is probing multiple ports (Reconnaissance)."""
        ip_ports = {}
        for p in packets:
            if p.source_ip not in ip_ports:
                ip_ports[p.source_ip] = set()
            ip_ports[p.source_ip].add(p.target_port)
        
        for ip, ports in ip_ports.items():
            if len(ports) > port_threshold:
                return ThreatAlert(
                    id=f"PSC-{int(time.time())}",
                    type="Port Scan",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"Reconnaissance detected: {len(ports)} distinct ports scanned.",
                    timestamp=datetime.now().isoformat()
                )
        return None

# --- Background Simulation Task ---

async def simulate_traffic_ingestion():
    """Background task to simulate a constant stream of network data."""
    global total_packets_processed
    while True:
        # Generate random "clean" traffic
        for _ in range(random.randint(5, 15)):
            packet = Packet(
                source_ip=f"192.168.1.{random.randint(1, 254)}",
                target_port=random.choice([80, 443, 22, 53]),
                protocol="TCP",
                payload_size=random.randint(64, 1500),
                timestamp=time.time()
            )
            telemetry_buffer.append(packet)
            total_packets_processed += 1
        
        # Occasionally simulate a threat burst
        if random.random() < 0.05:
            attacker_ip = "10.0.5.99"
            for _ in range(60):
                packet = Packet(
                    source_ip=attacker_ip,
                    target_port=random.randint(1000, 9000),
                    protocol="UDP",
                    payload_size=128,
                    timestamp=time.time()
                )
                telemetry_buffer.append(packet)
                total_packets_processed += 1

        # Prune old buffer data (keep last 5 seconds)
        now = time.time()
        while telemetry_buffer and (now - telemetry_buffer[0].timestamp > 5):
            telemetry_buffer.pop(0)
            
        # Run Heuristics
        ddos = ThreatEngine.detect_ddos(telemetry_buffer)
        if ddos: active_threats.insert(0, ddos)
        
        pscan = ThreatEngine.detect_port_scan(telemetry_buffer)
        if pscan: active_threats.insert(0, pscan)

        # Limit threat log size
        if len(active_threats) > 50: active_threats.pop()

        await asyncio.sleep(1)

# --- API Endpoints ---

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(simulate_traffic_ingestion())

@app.get("/telemetry/summary")
async def get_summary():
    """Returns real-time bandwidth and packet counts."""
    pps = len(telemetry_buffer) / 5  # Estimated Packets Per Second
    return {
        "status": "online",
        "pps": round(pps, 2),
        "total_processed": total_packets_processed,
        "active_alerts": len(active_threats)
    }

@app.get("/alerts", response_model=List[ThreatAlert])
async def get_alerts():
    """Returns the most recent security threats identified by the engine."""
    return active_threats

@app.get("/ai-insights", response_model=SecurityInsight)
async def get_ai_insights():
    """
    Simulates a call to an LLM (e.g., Gemini) that analyzes current 
    telemetry trends to provide a strategic recommendation.
    """
    pps = len(telemetry_buffer) / 5
    if pps > 20:
        return SecurityInsight(
            engine="Gemini-Flash-2.5",
            summary="Network load is 3x baseline. Heuristic engine flagged volume anomalies from subnet 10.0.x.x.",
            recommendation="Deploy temporary rate-limiting on Edge-Router-01. Inspect UDP traffic for amplification patterns."
        )
    return SecurityInsight(
        engine="Gemini-Flash-2.5",
        summary="Traffic is nominal. Latency is within 15ms. No lateral movement detected.",
        recommendation="Continue routine scanning. Ensure firewall definitions for Port 22 (SSH) are updated."
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
