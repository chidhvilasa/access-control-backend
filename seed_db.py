"""
Seed Database with Demo Data
Creates test communities, users, and keys
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder
import os

from models import Base, User, Device, Community, Membership, Keyset

# Database connection
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./access_control.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def seed_database():
    """Populate database with demo data"""
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        print("🌱 Seeding database...")
        
        # Create Communities
        print("\n📍 Creating communities...")
        communities = [
            Community(
                community_id="apt101",
                name="Apartment 101 Parking",
                description="Main apartment building parking access"
            ),
            Community(
                community_id="public_parking",
                name="Public Parking Lot",
                description="City public parking facility"
            ),
            Community(
                community_id="gym_access",
                name="Gym Access",
                description="24/7 gym facility access"
            )
        ]
        
        for comm in communities:
            existing = db.query(Community).filter(
                Community.community_id == comm.community_id
            ).first()
            if not existing:
                db.add(comm)
                print(f"  ✓ Created: {comm.name}")
        
        db.commit()
        
        # Generate Keys for Communities
        print("\n🔑 Generating Ed25519 keypairs...")
        for comm in communities:
            existing_key = db.query(Keyset).filter(
                Keyset.community_id == comm.community_id,
                Keyset.active == True
            ).first()
            
            if not existing_key:
                signing_key = SigningKey.generate()
                private_key_b64 = signing_key.encode(encoder=Base64Encoder).decode()
                public_key_b64 = signing_key.verify_key.encode(encoder=Base64Encoder).decode()
                
                keyset = Keyset(
                    community_id=comm.community_id,
                    algo="ED25519",
                    public_key=public_key_b64,
                    private_key=private_key_b64,
                    active=True
                )
                db.add(keyset)
                print(f"  ✓ Generated keys for: {comm.community_id}")
                print(f"    Public key: {public_key_b64[:32]}...")
        
        db.commit()
        
        # Create Demo Users
        print("\n👤 Creating demo users...")
        demo_users = [
            {"user_id": "user001", "phone": "+1234567890"},
            {"user_id": "user002", "phone": "+1234567891"},
            {"user_id": "user003", "phone": "+1234567892"}
        ]
        
        for user_data in demo_users:
            existing = db.query(User).filter(User.user_id == user_data["user_id"]).first()
            if not existing:
                user = User(**user_data)
                db.add(user)
                print(f"  ✓ Created user: {user.user_id}")
        
        db.commit()
        
        # Create Demo Devices
        print("\n📱 Creating demo devices...")
        demo_devices = [
            {"device_id": "android_device_001", "user_id": "user001", "platform": "android"},
            {"device_id": "android_device_002", "user_id": "user002", "platform": "android"},
            {"device_id": "android_device_003", "user_id": "user003", "platform": "android"}
        ]
        
        for device_data in demo_devices:
            existing = db.query(Device).filter(
                Device.device_id == device_data["device_id"]
            ).first()
            if not existing:
                device = Device(**device_data)
                db.add(device)
                print(f"  ✓ Created device: {device.device_id}")
        
        db.commit()
        
        # Create Demo Memberships (some approved, some pending)
        print("\n🎫 Creating memberships...")
        demo_memberships = [
            # User 1: Approved for apt101
            {"user_id": "user001", "community_id": "apt101", "status": "approved", "approved_by": "admin"},
            # User 2: Approved for public_parking
            {"user_id": "user002", "community_id": "public_parking", "status": "approved", "approved_by": "admin"},
            # User 3: Pending for gym_access
            {"user_id": "user003", "community_id": "gym_access", "status": "pending"},
        ]
        
        for mem_data in demo_memberships:
            existing = db.query(Membership).filter(
                Membership.user_id == mem_data["user_id"],
                Membership.community_id == mem_data["community_id"]
            ).first()
            if not existing:
                membership = Membership(**mem_data)
                db.add(membership)
                status_emoji = "✓" if mem_data["status"] == "approved" else "⏳"
                print(f"  {status_emoji} {mem_data['user_id']} → {mem_data['community_id']} ({mem_data['status']})")
        
        db.commit()
        
        # Summary
        print("\n" + "="*60)
        print("✅ Database seeded successfully!")
        print("="*60)
        print(f"\n📊 Summary:")
        print(f"  Communities: {db.query(Community).count()}")
        print(f"  Users: {db.query(User).count()}")
        print(f"  Devices: {db.query(Device).count()}")
        print(f"  Memberships: {db.query(Membership).count()}")
        print(f"  Keysets: {db.query(Keyset).count()}")
        
        print(f"\n🔐 Admin Credentials:")
        print(f"  Username: admin")
        print(f"  Password: admin123")
        
        print(f"\n🧪 Test Users:")
        for user_data in demo_users:
            print(f"  {user_data['user_id']} - {user_data['phone']}")
        
        print(f"\n🏢 Communities:")
        for comm in communities:
            print(f"  {comm.community_id} - {comm.name}")
        
    except Exception as e:
        print(f"\n❌ Error seeding database: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()