from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta, date
import base64
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
import uvicorn
from models import *
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Access Control API", version="1.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE_URL = "sqlite:///./access_control.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables
Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize keys if needed
def init_keys(db: Session):
    communities = ['apt101', 'public_parking', 'gym_access']
    
    for comm_id in communities:
        # Check if community exists
        comm = db.query(Community).filter(Community.community_id == comm_id).first()
        if not comm:
            # Create community
            comm_data = {
                'apt101': {'name': 'Apartment 101 Parking', 'description': 'Resident parking access'},
                'public_parking': {'name': 'Public Parking', 'description': 'Public visitor parking'},
                'gym_access': {'name': 'Gym Access', 'description': '24/7 gym facility'}
            }
            
            comm = Community(
                community_id=comm_id,
                name=comm_data[comm_id]['name'],
                description=comm_data[comm_id]['description']
            )
            db.add(comm)
        
        # Check if keyset exists
        keyset = db.query(Keyset).filter(
            Keyset.community_id == comm_id,
            Keyset.active == True
        ).first()
        
        if not keyset:
            # Generate new keypair
            signing_key = SigningKey.generate()
            public_key = signing_key.verify_key.encode(encoder=Base64Encoder).decode()
            private_key = signing_key.encode(encoder=Base64Encoder).decode()
            
            keyset = Keyset(
                community_id=comm_id,
                algo="ED25519",
                public_key=public_key,
                private_key=private_key
            )
            db.add(keyset)
            logger.info(f"Generated keys for {comm_id}")
    
    db.commit()

# Initialize on startup
@app.on_event("startup")
def startup():
    db = SessionLocal()
    try:
        init_keys(db)
        logger.info("✓ Database initialized")
    finally:
        db.close()

@app.get("/")
def root():
    return {
        "message": "Access Control API",
        "version": "1.0",
        "status": "running"
    }

@app.post("/register_device")
def register_device(request: RegisterDeviceRequest, db: Session = Depends(get_db)):
    """Register a new mobile device"""
    
    # Check if user exists, create if not
    user = db.query(User).filter(User.user_id == request.user_id).first()
    if not user:
        user = User(user_id=request.user_id, phone=request.phone)
        db.add(user)
    
    # Check if device already registered
    device = db.query(Device).filter(Device.device_id == request.device_id).first()
    if device:
        return {"success": False, "message": "Device already registered"}
    
    # Register device
    device = Device(
        device_id=request.device_id,
        user_id=request.user_id,
        platform=request.platform
    )
    db.add(device)
    
    # Create pending membership
    membership = Membership(
        user_id=request.user_id,
        community_id=request.community_id,
        status="pending"
    )
    db.add(membership)
    
    db.commit()
    
    logger.info(f"Device registered: {request.device_id} for user {request.user_id}")
    return {"success": True, "message": "Device registered. Waiting for admin approval."}

@app.get("/admin/approve_device/{user_id}/{community_id}")
def approve_device(user_id: str, community_id: str, db: Session = Depends(get_db)):
    """Approve device access (admin only)"""
    
    membership = db.query(Membership).filter(
        Membership.user_id == user_id,
        Membership.community_id == community_id
    ).first()
    
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")
    
    membership.status = "approved"
    membership.updated_at = datetime.utcnow()
    db.commit()
    
    logger.info(f"Approved {user_id} for {community_id}")
    return {"success": True, "message": f"User approved for {community_id}"}

@app.get("/my_communities")
def get_my_communities(x_device_id: str = Header(..., alias="X-Device-ID"), db: Session = Depends(get_db)):
    """Get communities user has access to"""
    
    device = db.query(Device).filter(Device.device_id == x_device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not registered")
    
    memberships = db.query(Membership).filter(Membership.user_id == device.user_id).all()
    
    communities = []
    for membership in memberships:
        comm = db.query(Community).filter(Community.community_id == membership.community_id).first()
        if comm:
            communities.append(CommunityResponse(
                community_id=comm.community_id,
                name=comm.name,
                description=comm.description,
                status=membership.status
            ))
    
    return communities

@app.post("/sign_token")
def sign_token(request: SignTokenRequest, db: Session = Depends(get_db)):
    """Generate signed token for access"""
    
    # Verify device
    device = db.query(Device).filter(Device.device_id == request.device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not registered")
    
    # Check membership
    membership = db.query(Membership).filter(
        Membership.user_id == request.user_id,
        Membership.community_id == request.community_id
    ).first()
    
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this community")
    
    if membership.status != "approved":
        raise HTTPException(status_code=403, detail="Access not approved")
    
    # Get signing key
    keyset = db.query(Keyset).filter(
        Keyset.community_id == request.community_id,
        Keyset.active == True
    ).first()
    
    if not keyset:
        raise HTTPException(status_code=500, detail="No active keyset")
    
    # Create signing key from stored private key
    signing_key = SigningKey(keyset.private_key.encode(), encoder=Base64Encoder)
    
    # Create token payload
    expires_at = int((datetime.utcnow() + timedelta(seconds=30)).timestamp())
    payload = {
        'user_id': request.user_id,
        'device_id': request.device_id,
        'community_id': request.community_id,
        'type': request.type,
        'expires_at': expires_at
    }
    
    # Sign token
    payload_str = json.dumps(payload, sort_keys=True)
    signature = signing_key.sign(payload_str.encode()).signature
    
    token = base64.b64encode(
        payload_str.encode() + b'.' + signature
    ).decode()
    
    logger.info(f"Token generated for {request.user_id} - {request.community_id}")
    
    return SignTokenResponse(token=token, expires_at=expires_at)

@app.get("/pi/config")
def get_pi_config(pi_id: str, db: Session = Depends(get_db)):
    """Get configuration for Pi device"""
    
    communities = db.query(Community).all()
    keysets_dict = {}
    communities_list = []
    
    for comm in communities:
        communities_list.append({
            'community_id': comm.community_id,
            'name': comm.name,
            'description': comm.description
        })
        
        keyset = db.query(Keyset).filter(
            Keyset.community_id == comm.community_id,
            Keyset.active == True
        ).first()
        
        if keyset:
            keysets_dict[comm.community_id] = keyset.public_key
    
    return {
        'communities': communities_list,
        'keysets': keysets_dict
    }

@app.post("/pi/log_access")
def log_access(event: PiEventRequest, db: Session = Depends(get_db)):
    """Log access event from Pi"""
    
    log_entry = Event(
        user_id=event.user_id,
        device_id=event.device_id,
        community_id=event.community_id,
        type=event.type,
        timestamp=event.timestamp,
        verified=event.verified
    )
    
    db.add(log_entry)
    db.commit()
    
    logger.info(f"Access logged: {event.type} - {'SUCCESS' if event.verified else 'DENIED'}")
    return {"success": True, "event_id": log_entry.event_id}

@app.post("/pi/log_nfc_detection")
def log_nfc_detection(
    pi_id: str,
    uid: str,
    db: Session = Depends(get_db)
):
    """Log NFC card detection (even without authentication)"""
    
    log_entry = Event(
        user_id="unknown",
        device_id=uid,
        community_id="unknown",
        type="nfc_detected",
        pi_id=pi_id,
        timestamp=datetime.utcnow(),
        verified=False
    )
    
    db.add(log_entry)
    db.commit()
    
    logger.info(f"NFC Detection logged: {uid} at {pi_id}")
    return {"success": True, "event_id": log_entry.event_id, "message": "NFC detection logged"}

@app.get("/my_logs")
def get_my_logs(x_device_id: str = Header(..., alias="X-Device-ID"), limit: int = 50, db: Session = Depends(get_db)):
    """Get access logs for user"""
    
    device = db.query(Device).filter(Device.device_id == x_device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not registered")
    
    events = db.query(Event).filter(
        Event.user_id == device.user_id
    ).order_by(Event.timestamp.desc()).limit(limit).all()
    
    return [EventResponse(
        event_id=e.event_id,
        community_id=e.community_id,
        type=e.type,
        timestamp=e.timestamp,
        pi_id=e.pi_id
    ) for e in events]

@app.get("/admin/logs")
def get_all_logs(limit: int = 100, db: Session = Depends(get_db)):
    """Get all access logs (admin only)"""
    
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all()
    
    return [{
        'event_id': e.event_id,
        'user_id': e.user_id,
        'device_id': e.device_id,
        'community_id': e.community_id,
        'type': e.type,
        'timestamp': e.timestamp.isoformat(),
        'verified': e.verified,
        'pi_id': e.pi_id
    } for e in events]

@app.get("/admin/stats")
def get_stats(db: Session = Depends(get_db)):
    """Get system statistics"""
    
    # Count users
    total_users = db.query(User).count()
    
    # Count devices
    total_devices = db.query(Device).count()
    
    # Count today's events
    today = date.today()
    events_today = db.query(Event).filter(
        func.date(Event.timestamp) == today
    ).count()
    
    # Calculate success rate
    total_events = db.query(Event).count()
    successful_events = db.query(Event).filter(Event.verified == True).count()
    success_rate = (successful_events / total_events * 100) if total_events > 0 else 100
    
    # Recent activity
    recent_events = db.query(Event).order_by(Event.timestamp.desc()).limit(10).all()
    
    return {
        'total_users': total_users,
        'total_devices': total_devices,
        'events_today': events_today,
        'success_rate': round(success_rate, 1),
        'total_events': total_events,
        'successful_events': successful_events,
        'recent_activity': [{
            'user_id': e.user_id,
            'type': e.type,
            'timestamp': e.timestamp.isoformat(),
            'verified': e.verified,
            'community_id': e.community_id
        } for e in recent_events]
    }

@app.get("/admin/devices")
def list_devices(db: Session = Depends(get_db)):
    """List all registered devices (admin)"""
    devices = db.query(Device).all()
    return [
        {
            'device_id': d.device_id,
            'user_id': d.user_id,
            'platform': d.platform,
            'registered_at': d.registered_at.isoformat()
        }
        for d in devices
    ]

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    """Serve the admin dashboard"""
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NFC Access Control - Admin Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 1.1em;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #667eea;
            border-bottom: 2px solid #e0e0e0;
        }
        
        td {
            padding: 15px;
            border-bottom: 1px solid #f0f0f0;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .status {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }
        
        .status.verified {
            background: #d4edda;
            color: #155724;
        }
        
        .status.denied {
            background: #f8d7da;
            color: #721c24;
        }
        
        .status.detected {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            transition: all 0.3s;
        }
        
        .refresh-btn:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .empty {
            text-align: center;
            padding: 40px;
            color: #999;
        }
        
        .last-updated {
            text-align: right;
            color: #999;
            font-size: 0.9em;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 NFC Access Control Dashboard</h1>
            <p>Real-time monitoring of access events and user management</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Users</h3>
                <div class="number" id="totalUsers">-</div>
            </div>
            <div class="stat-card">
                <h3>Active Devices</h3>
                <div class="number" id="totalDevices">-</div>
            </div>
            <div class="stat-card">
                <h3>Events Today</h3>
                <div class="number" id="eventsToday">-</div>
            </div>
            <div class="stat-card">
                <h3>Success Rate</h3>
                <div class="number" id="successRate">-</div>
            </div>
        </div>
        
        <div class="section">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>📱 Registered Devices</h2>
                <button class="refresh-btn" onclick="loadData()">🔄 Refresh</button>
            </div>
            <div id="devicesContent">
                <div class="loading">
                    <div class="spinner"></div>
                    <p>Loading devices...</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Recent Access Logs (Last 100)</h2>
            <div id="logsContent">
                <div class="loading">
                    <div class="spinner"></div>
                    <p>Loading logs...</p>
                </div>
            </div>
            <div class="last-updated" id="lastUpdated"></div>
        </div>
    </div>
    
    <script>
        const API_URL = window.location.origin;
        
        async function loadData() {
            await Promise.all([
                loadStats(),
                loadDevices(),
                loadLogs()
            ]);
            document.getElementById('lastUpdated').textContent = 'Last updated: ' + new Date().toLocaleString();
        }
        
        async function loadStats() {
            try {
                const response = await fetch(`${API_URL}/admin/stats`);
                const stats = await response.json();
                
                document.getElementById('totalUsers').textContent = stats.total_users;
                document.getElementById('totalDevices').textContent = stats.total_devices;
                document.getElementById('eventsToday').textContent = stats.events_today;
                document.getElementById('successRate').textContent = stats.success_rate + '%';
                
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }
        
        async function loadDevices() {
            try {
                const response = await fetch(`${API_URL}/admin/devices`);
                const devices = await response.json();
                
                if (devices.length === 0) {
                    document.getElementById('devicesContent').innerHTML = '<div class="empty">No devices registered yet</div>';
                    return;
                }
                
                let html = `
                    <table>
                        <thead>
                            <tr>
                                <th>User ID</th>
                                <th>Device ID</th>
                                <th>Platform</th>
                                <th>Registered At</th>
                            </tr>
                        </thead>
                        <tbody>
                `;
                
                devices.forEach(device => {
                    const date = new Date(device.registered_at).toLocaleString();
                    html += `
                        <tr>
                            <td><strong>${device.user_id}</strong></td>
                            <td><code>${device.device_id.substring(0, 20)}...</code></td>
                            <td>${device.platform}</td>
                            <td>${date}</td>
                        </tr>
                    `;
                });
                
                html += '</tbody></table>';
                document.getElementById('devicesContent').innerHTML = html;
                
            } catch (error) {
                document.getElementById('devicesContent').innerHTML = '<div class="empty">Error loading devices</div>';
                console.error('Error loading devices:', error);
            }
        }
        
        async function loadLogs() {
            try {
                const response = await fetch(`${API_URL}/admin/logs?limit=100`);
                const logs = await response.json();
                
                if (logs.length === 0) {
                    document.getElementById('logsContent').innerHTML = '<div class="empty">No access logs yet</div>';
                    return;
                }
                
                let html = `
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>User</th>
                                <th>Community</th>
                                <th>Type</th>
                                <th>Status</th>
                                <th>Pi ID</th>
                            </tr>
                        </thead>
                        <tbody>
                `;
                
                logs.forEach(log => {
                    const date = new Date(log.timestamp).toLocaleString();
                    const statusClass = log.verified ? 'verified' : 
                                       log.type === 'nfc_detected' ? 'detected' : 'denied';
                    const statusText = log.verified ? 'Granted' : 
                                      log.type === 'nfc_detected' ? 'Detected' : 'Denied';
                    
                    html += `
                        <tr>
                            <td>${date}</td>
                            <td>${log.user_id}</td>
                            <td>${log.community_id}</td>
                            <td>${log.type}</td>
                            <td><span class="status ${statusClass}">${statusText}</span></td>
                            <td>${log.pi_id || '-'}</td>
                        </tr>
                    `;
                });
                
                html += '</tbody></table>';
                document.getElementById('logsContent').innerHTML = html;
                
            } catch (error) {
                document.getElementById('logsContent').innerHTML = '<div class="empty">Error loading logs</div>';
                console.error('Error loading logs:', error);
            }
        }
        
        // Load data on page load
        loadData();
        
        // Auto-refresh every 10 seconds
        setInterval(loadData, 10000);
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)